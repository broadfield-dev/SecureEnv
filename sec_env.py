#!/usr/bin/env python3
"""
sec_env - Secure Environment Variable Manager

Self-contained AES-256-CBC encryption/decryption module using password-derived keys.
All password handling uses mutable bytearray buffers to securely wipe sensitive
material from memory after use, mitigating string immutability/interning risks.

Usage:
    import sec_env

    # Encrypt a raw .env file in-place
    sec_env.process()

    # Decrypt and load environment variables like python-dotenv
    sec_env.load()

    # Restore .env to plaintext (reverse encryption)
    sec_env.restore()

    # Get a callable unlock object for on-demand decryption
    unlocker = sec_env.unlock("my_password")
    db_pass = unlocker("DB_PASSWORD")

    # Direct single-key access
    api_key = sec_env.key("API_KEY", "my_password")
"""

import os
import re
import gc
import getpass
from pathlib import Path
from typing import Optional, Union, Callable

import base64
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_ENV_FILE = ".env.test"

# Encryption detection pattern (base64 with salt(16)+iv(16)+ct >= 32 bytes ~44 chars)
ENCRYPTED_PATTERN = re.compile(
    r'^[A-Za-z0-9+/=]{48,}$'
)


# ---------------------------------------------------------------------------
# Secure memory utilities
# ---------------------------------------------------------------------------

def _secure_wipe_bytearray(ba: Optional[bytearray]) -> None:
    """
    Overwrite a bytearray in-place with zeros, then release it.

    This is the core defense against password persistence in memory.
    Python strings are immutable and may be interned/cached; bytearray
    is mutable and can be reliably zeroed.

    Args:
        ba: The bytearray to wipe. If None, no-op.
    """
    if ba is None:
        return
    try:
        length = len(ba)
        if length > 0:
            ba[:] = b'\x00' * length
    except Exception:
        pass  # Best-effort; some buffers may be read-only
    gc.collect()


def _make_bytearray(password: str) -> bytearray:
    """
    Convert a string password to a mutable bytearray immediately.
    The original string reference should be dropped (set to None)
    before returning so no immutable copy remains accessible.
    """
    return bytearray(password.encode('utf-8'))


# ---------------------------------------------------------------------------
# Core encryption/decryption (accept password as bytes-like)
# ---------------------------------------------------------------------------

def encrypt_with_password(plaintext: str, password: Union[str, bytes, bytearray]) -> str:
    """
    Encrypt plaintext using AES-256-CBC with a password-derived key.

    Args:
        plaintext: String to encrypt.
        password: Password for key derivation. Can be str, bytes, or bytearray.
                 If str is passed, it will be encoded to bytes immediately.
                 **Warning**: passing a str risks leaving immutable copies in
                 memory; prefer bytearray from _make_bytearray().

    Returns:
        Base64-encoded string containing salt + IV + ciphertext.
    """
    # Convert password to bytes if needed
    if isinstance(password, str):
        pw_bytes = password.encode('utf-8')
    else:
        pw_bytes = password

    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    key = kdf.derive(pw_bytes)

    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext.encode('utf-8')) + padder.finalize()

    ct = encryptor.update(padded_data) + encryptor.finalize()

    return base64.b64encode(salt + iv + ct).decode('utf-8')


def decrypt_with_password(encrypted_text: str, password: Union[str, bytes, bytearray]) -> str:
    """
    Decrypt data that was encrypted with encrypt_with_password.

    Args:
        encrypted_text: Base64 string containing salt + IV + ciphertext.
        password: Password for key derivation. Can be str, bytes, or bytearray.
                 Prefer bytearray from _make_bytearray().

    Returns:
        Decrypted plaintext string.
    """
    if isinstance(password, str):
        pw_bytes = password.encode('utf-8')
    else:
        pw_bytes = password

    data = base64.b64decode(encrypted_text)
    salt = data[:16]
    iv = data[16:32]
    ct = data[32:]

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    key = kdf.derive(pw_bytes)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ct) + decryptor.finalize()

    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    return plaintext.decode('utf-8')


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _is_encrypted(value: str) -> bool:
    """Check if a value appears to be already encrypted (base64-like pattern)."""
    return bool(ENCRYPTED_PATTERN.match(value.strip()))


def _load_env_file(env_path: str) -> dict:
    """
    Parse a .env file and return a dict of key-value pairs.
    Preserves key order. Supports comments (#), quoted values, and blank lines.
    """
    env_dict = {}
    path = Path(env_path)
    if not path.exists():
        raise FileNotFoundError(f"{env_path} not found")

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip()
            # Remove surrounding quotes if present
            if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
                value = value[1:-1]
            env_dict[key] = value
    return env_dict


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def process(
    password: Optional[Union[str, bytearray]] = None,
    env_path: Optional[str] = None,
    in_place: bool = True
) -> None:
    """
    Encrypt all plaintext values in a .env file, overwriting the file in-place.

    Args:
        password: Password for encryption. If None, prompts interactively.
        env_path: Path to the .env file (defaults to '.env' in current directory).
        in_place: If True, overwrite the original file; otherwise write to a new file.

    The function detects already-encrypted values and leaves them unchanged.
    Comments, blank lines, and formatting are preserved.
    """
    if env_path is None:
        env_path = str(Path.cwd() / DEFAULT_ENV_FILE)

    # --- Password handling with bytearray ---
    pw_ba: Optional[bytearray] = None
    if password is None:
        pw_str = getpass.getpass("Encryption password: ")
        pw_ba = _make_bytearray(pw_str)
        pw_str = None  # Drop the immutable string reference
    elif isinstance(password, str):
        pw_ba = _make_bytearray(password)
        password = None  # Drop the caller's string reference
    else:
        pw_ba = password  # Already a bytearray; caller is responsible

    path = Path(env_path)
    if not path.exists():
        _secure_wipe_bytearray(pw_ba)
        raise FileNotFoundError(f"{env_path} not found")

    # Read file and process line by line, preserving comments/blanks
    lines = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                lines.append(line)
                continue
            if "=" not in stripped:
                lines.append(line)
                continue

            key, _, value = stripped.partition("=")
            key = key.strip()
            value = value.strip()

            # Remove surrounding quotes for detection
            raw_value = value
            if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
                raw_value = value[1:-1]

            if _is_encrypted(raw_value):
                lines.append(line)
                continue

            # Encrypt the value using bytearray password directly
            encrypted = encrypt_with_password(raw_value, pw_ba)
            indent = line[:len(line) - len(line.lstrip())]
            new_line = f"{indent}{key}={encrypted}\n"
            lines.append(new_line)

    # Securely wipe password from memory
    if pw_ba is not None:
        _secure_wipe_bytearray(pw_ba)
        pw_ba = None
    gc.collect()

    # Write output
    if in_place:
        out_path = path
    else:
        out_path = path.with_suffix(".env.encrypted")

    with open(out_path, "w", encoding="utf-8") as f:
        f.writelines(lines)

    print(f"Processed {env_path} -> {out_path}")


def load(
    password: Optional[Union[str, bytearray]] = None,
    env_path: Optional[str] = None
) -> dict:
    """
    Load and decrypt all environment variables from an encrypted .env file.

    Similar to python-dotenv's load_dotenv(), but decrypts values using the
    given password. Decrypted values are set as environment variables via os.environ.

    Args:
        password: Password for decryption. If None, prompts interactively.
        env_path: Path to the .env file (defaults to '.env' in current directory).

    Returns:
        dict of all decrypted key-value pairs.
        Plaintext (non-encrypted) values in the .env are passed through as-is.
    """
    if env_path is None:
        env_path = str(Path.cwd() / DEFAULT_ENV_FILE)

    # --- Password handling with bytearray ---
    pw_ba: Optional[bytearray] = None
    if password is None:
        pw_str = getpass.getpass("Decryption password: ")
        pw_ba = _make_bytearray(pw_str)
        pw_str = None
    elif isinstance(password, str):
        pw_ba = _make_bytearray(password)
        password = None
    else:
        pw_ba = password

    raw_dict = _load_env_file(env_path)

    decrypted_dict = {}
    for key, value in raw_dict.items():
        if _is_encrypted(value):
            try:
                plaintext = decrypt_with_password(value, pw_ba)
                decrypted_dict[key] = plaintext
            except Exception as e:
                print(f"Warning: Failed to decrypt {key}: {e}")
                decrypted_dict[key] = value
        else:
            decrypted_dict[key] = value

    # Set all values in os.environ
    for key, val in decrypted_dict.items():
        os.environ[key] = val

    # Securely wipe password
    if pw_ba is not None:
        _secure_wipe_bytearray(pw_ba)
        pw_ba = None
    gc.collect()

    return decrypted_dict


def unlock(password: Union[str, bytearray]) -> Callable:
    """
    Create a callable unlocker object that can decrypt individual environment
    variables on demand.

    Args:
        password: The decryption password (str or bytearray).
                 If str is passed, it is converted to bytearray immediately.
                 The original string reference should be dropped by the caller.

    Returns:
        An _Unlocker instance that behaves like a callable function.
        The password is stored internally as a mutable bytearray and is
        securely wiped when the unlocker object is deleted or garbage-collected.

    Example:
        unlocker = sec_env.unlock("mypassword")
        value = unlocker("SECRET_KEY")
        del unlocker  # triggers __del__ which wipes the password buffer
    """
    env_path = str(Path.cwd() / DEFAULT_ENV_FILE)
    raw_dict = _load_env_file(env_path)

    # Convert str to bytearray immediately
    if isinstance(password, str):
        pw_ba = _make_bytearray(password)
        password = None
    else:
        pw_ba = bytearray(password)  # Copy so we control the buffer lifecycle

    class _Unlocker:
        """
        Callable object that decrypts environment variable values using a
        stored password (as mutable bytearray).
        """

        def __init__(self, pw_ba: bytearray, raw_dict: dict, env_path: str):
            self._pw = pw_ba
            self._raw_dict = raw_dict
            self._env_path = env_path

        def __call__(self, key_name: str) -> str:
            """Decrypt and return the value for the given key name."""
            value = self._raw_dict.get(key_name)
            if value is None:
                raise KeyError(f"Key '{key_name}' not found in {self._env_path}")

            if _is_encrypted(value):
                try:
                    # Pass bytearray directly - no decode needed
                    return decrypt_with_password(value, self._pw)
                except Exception as e:
                    raise ValueError(f"Failed to decrypt '{key_name}': {e}")
            else:
                return value

        def __del__(self):
            """Securely wipe the password buffer from memory on deletion."""
            _secure_wipe_bytearray(self._pw)
            self._pw = None
            gc.collect()

    return _Unlocker(pw_ba, raw_dict, env_path)


def key(
    key_name: str,
    password: Union[str, bytearray],
    env_path: Optional[str] = None
) -> str:
    """
    Directly retrieve and decrypt a single environment variable by name.

    This is a single-shot function: it loads the .env file, finds the key,
    decrypts it, and returns the plaintext value. The password is securely
    wiped from memory before returning.

    Args:
        key_name: The name of the environment variable (e.g. "DB_PASSWORD").
        password: The decryption password (str or bytearray).
        env_path: Path to the .env file (defaults to '.env' in current directory).

    Returns:
        The decrypted plaintext value.

    Raises:
        KeyError: If the key is not found in the .env file.
        ValueError: If decryption fails.
    """
    if env_path is None:
        env_path = str(Path.cwd() / DEFAULT_ENV_FILE)

    # Convert str to bytearray immediately
    if isinstance(password, str):
        pw_ba = _make_bytearray(password)
        password = None  # Drop caller's string reference
    else:
        pw_ba = password

    try:
        raw_dict = _load_env_file(env_path)
        value = raw_dict.get(key_name)

        if value is None:
            raise KeyError(f"Key '{key_name}' not found in {env_path}")

        if _is_encrypted(value):
            try:
                plaintext = decrypt_with_password(value, pw_ba)
                return plaintext
            except Exception as e:
                raise ValueError(f"Failed to decrypt '{key_name}': {e}")
        else:
            return value
    finally:
        # Always wipe password, even on error
        _secure_wipe_bytearray(pw_ba)
        pw_ba = None
        gc.collect()


# ---------------------------------------------------------------------------
# restore function - reverse encryption in-place
# ---------------------------------------------------------------------------

def restore(
    password: Optional[Union[str, bytearray]] = None,
    env_path: Optional[str] = None
) -> None:
    """
    Decrypt all encrypted values in a .env file back to plaintext, overwriting
    the file in-place. This reverses the encryption performed by process().

    Args:
        password: Password for decryption. If None, prompts interactively.
        env_path: Path to the .env file (defaults to '.env' in current directory).

    The function preserves comments, blank lines, and formatting.
    Plaintext values (non-encrypted) are left unchanged.
    """
    if env_path is None:
        env_path = str(Path.cwd() / DEFAULT_ENV_FILE)

    # --- Password handling with bytearray ---
    pw_ba: Optional[bytearray] = None
    if password is None:
        pw_str = getpass.getpass("Decryption password for restore: ")
        pw_ba = _make_bytearray(pw_str)
        pw_str = None
    elif isinstance(password, str):
        pw_ba = _make_bytearray(password)
        password = None
    else:
        pw_ba = password

    path = Path(env_path)
    if not path.exists():
        _secure_wipe_bytearray(pw_ba)
        raise FileNotFoundError(f"{env_path} not found")

    # Read file and process line by line
    lines = []
    decrypt_errors = 0
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                lines.append(line)
                continue
            if "=" not in stripped:
                lines.append(line)
                continue

            key, _, value = stripped.partition("=")
            key = key.strip()
            value = value.strip()

            # Remove surrounding quotes for detection
            raw_value = value
            if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
                raw_value = value[1:-1]

            if not _is_encrypted(raw_value):
                lines.append(line)
                continue

            # Decrypt the value
            try:
                plaintext = decrypt_with_password(raw_value, pw_ba)
                indent = line[:len(line) - len(line.lstrip())]
                # Preserve original quoting if detected
                if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
                    new_line = f"{indent}{key}={value[0]}{plaintext}{value[0]}\n"
                else:
                    new_line = f"{indent}{key}={plaintext}\n"
                lines.append(new_line)
            except Exception as e:
                decrypt_errors += 1
                print(f"Warning: Failed to decrypt {key}: {e}")
                lines.append(line)  # Keep original line on failure

    # Securely wipe password from memory
    if pw_ba is not None:
        _secure_wipe_bytearray(pw_ba)
        pw_ba = None
    gc.collect()

    # Write output
    with open(path, "w", encoding="utf-8") as f:
        f.writelines(lines)

    if decrypt_errors:
        print(f"Restore completed with {decrypt_errors} decryption error(s).")
    else:
        print(f"Restored {env_path} to plaintext.")
