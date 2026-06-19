# SecureEnv 🔐

**Encrypt your `.env` files. Protect secrets from LLMs and system exfiltration.**

SecureEnv is a Python module that encrypts all sensitive values in your `.env` files using **AES-256-CBC** encryption. It provides a drop-in replacement workflow similar to `python-dotenv`, but with the critical difference that secrets are never stored in plaintext on disk.

[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Cryptography](https://img.shields.io/badge/crypto-AES--256--CBC-green)](https://cryptography.io/)

---

## 🌟 Why SecureEnv?

Most developers store secrets in plaintext `.env` files. If an LLM, CI/CD pipeline, or attacker gains file system access, those secrets are immediately compromised. **SecureEnv encrypts every value** so that:

- Secrets are **always encrypted on disk** — only decrypted in memory when explicitly requested.
- Passwords are handled as **mutable bytearrays** and zeroed out immediately after use.
- Your workflow stays the same — just replace `load_dotenv()` with `sec_env.load()`.

> **Ideal for**: AI/LLM project directories, shared development environments, CI/CD pipelines, and any scenario where `.env` files might be exposed to untrusted processes.

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| **🔐 AES-256-CBC Encryption** | Industry-standard symmetric encryption using PBKDF2 key derivation (100K iterations) |
| **🔄 Drop-in Replacement** | `sec_env.load()` works just like `python-dotenv.load_dotenv()` |
| **↩️ Restore to Plaintext** | `sec_env.restore()` reverses encryption, returning `.env` to its original state |
| **🔑 Flexible Access** | Load all vars at once, or decrypt individual keys on-demand |
| **🧹 Memory Safety** | All passwords handled as mutable `bytearray` objects; zeroed out immediately after use |
| **📝 Preserves Formatting** | Comments, blank lines, and key ordering are preserved in the encrypted `.env` file |
| **🔍 Mixed Content** | Handles `.env` files with both encrypted and plaintext values |
| **🛡️ Defense in Depth** | Multiple secure-wipe calls with garbage collection after sensitive operations |
| **📦 Self-Contained** | No external dependencies beyond `cryptography` — all crypto functions included inline |

---

## 📦 Installation

```bash
pip install cryptography
```

Then copy `sec_env.py` into your project:

```bash
cp sec_env.py your_project/
```

---

## 🚀 Quick Start

### 1. Encrypt your existing `.env` file

Say you have a plaintext `.env`:
```bash
# .env (PLAINTEXT — NOT SAFE!)
DATABASE_URL=postgresql://user:pass@localhost/db
API_KEY=sk-1234abcd5678efgh
SECRET_TOKEN=s3cr3t_t0k3n
```

Run from Python:

```python
import sec_env

# Encrypt ALL values in-place
sec_env.process()  # Prompts for password

# Or pass password directly to avoid prompting
sec_env.process("my_password")
```

After encryption, your `.env` looks like this:
```bash
# .env (ENCRYPTED — SAFE!)
DATABASE_URL=U2FsdGVkX18+ABC123...
API_KEY=U2FsdGVkX18+DEF456...
SECRET_TOKEN=U2FsdGVkX18+GHI789...
```

### 2. Load and decrypt into environment

```python
import os
import sec_env

# Load all decrypted values into os.environ
env_vars = sec_env.load()  # Prompts for password

# Now available like normal environment variables
print(os.getenv("DATABASE_URL"))
# postgresql://user:pass@localhost/db
```

### 3. Restore .env to plaintext (reverse encryption)

```python
import sec_env

# Decrypt all values back to original plaintext in-place
sec_env.restore()  # Prompts for password

# Or pass password directly
sec_env.restore("my_password")
```

After restore, the `.env` file is back to its original plaintext state.

### 4. On-demand decryption with unlocker

```python
import sec_env

# Get a callable unlocker object
open_env = sec_env.unlock("my_secret_password")

# Decrypt individual keys on-demand
db_url = open_env("DATABASE_URL")
api_key = open_env("API_KEY")
secret = open_env("SECRET_TOKEN")

# Password is wiped when unlocker goes out of scope
del open_env  # Forces immediate wipe + garbage collection
```

### 5. Single-key access

```python
import sec_env

# Decrypt just ONE key without loading everything
db_password = sec_env.key("DATABASE_URL", "my_secret_password")
```

---

## 📖 API Reference

### `sec_env.process(password=None, env_path=None, in_place=True)`

Encrypts all plaintext values in a `.env` file. Already-encrypted values are left unchanged. Preserves comments, blank lines, and key ordering.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `password` | `str`, `bytearray`, or `None` | `None` | Encryption password. `None` = prompt via `getpass` |
| `env_path` | `str` or `None` | `None` | Path to `.env` file. `None` = `./.env` in current directory |
| `in_place` | `bool` | `True` | If `True`, overwrite the original file. Otherwise writes `.env.encrypted` |

---

### `sec_env.load(password=None, env_path=None)`

Decrypts all values and sets them as environment variables via `os.environ`. Returns a dictionary of all key-value pairs.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `password` | `str`, `bytearray`, or `None` | `None` | Decryption password. `None` = prompt via `getpass` |
| `env_path` | `str` or `None` | `None` | Path to `.env` file. `None` = `./.env` |

**Returns**: `dict` — all decrypted key-value pairs.

---

### `sec_env.restore(password=None, env_path=None)`

Decrypts all encrypted values in a `.env` file back to plaintext, overwriting the file in-place. Reverses the encryption performed by `process()`.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `password` | `str`, `bytearray`, or `None` | `None` | Decryption password. `None` = prompt via `getpass` |
| `env_path` | `str` or `None` | `None` | Path to `.env` file. `None` = `./.env` |

**Behavior:**
- Decrypts all encrypted values back to plaintext in-place.
- Plaintext values are left unchanged.
- Preserves comments, blank lines, and formatting.
- If a decryption error occurs, a warning is printed and the original encrypted line is preserved.
- Password is securely wiped from memory after the operation completes.

**Example:**
```python
# Encrypt
sec_env.process("mypassword")

# Later, restore to plaintext
sec_env.restore("mypassword")
# .env is now back to its original plaintext state
```

---

### `sec_env.unlock(password)`

Returns a callable `_Unlocker` object for on-demand key decryption. The unlocker holds an internal **copy** of the password as a bytearray, so the original is never modified.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `password` | `str` or `bytearray` | *required* | Decryption password |

**Returns**: `_Unlocker` — callable that takes a key name and returns the decrypted value.

```python
unlocker = sec_env.unlock("password")
value = unlocker("MY_KEY")  # Decrypt individual key
```

The password is securely wiped when the unlocker is deleted or garbage collected.

---

### `sec_env.key(key_name, password, env_path=None)`

Direct, single-shot decryption of one environment variable. Password is wiped immediately after use.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `key_name` | `str` | *required* | The environment variable name to decrypt |
| `password` | `str` or `bytearray` | *required* | Decryption password |
| `env_path` | `str` or `None` | `None` | Custom path to `.env` file |

**Returns**: `str` — the decrypted value.

**Raises**: `KeyError` if the key is not found in the `.env` file.

---

## 🛡️ Security Architecture

### Password Lifecycle

```
User Input (str)  ──→  _make_bytearray()  ──→  bytearray   ──→  AES decrypt  ──→  _secure_wipe()
(ephemeral)                │                                  │                      │
                           │                                  │                      │
                    Original string       Internal buffer     │               Buffer zeroed
                    reference dropped     passed to crypto    │               in-place
                                                                                      ▼
                                                                              gc.collect()
```

1. **Input Boundary**: Password arrives as a Python string (from `getpass.getpass()` or user argument). This is the only moment it exists as an immutable string.
2. **Immediate Conversion**: `_make_bytearray()` converts the string to a mutable `bytearray` and drops the original string reference.
3. **Crypto Operations**: The bytearray is passed directly to encryption/decryption functions — no `.encode()` copies are created.
4. **Secure Wipe**: `_secure_wipe_bytearray()` overwrites the buffer in-place with zero bytes (`ba[:] = b'\x00' * len(ba)`) and calls `gc.collect()`.
5. **Exception Safety**: Even if an exception is raised, all public functions wipe the password in `finally` blocks before propagating the error.

### What SecureEnv Protects Against

| Threat | Mitigated? | Details |
|--------|------------|---------|
| 🔍 Plaintext `.env` on disk | ✅ **Yes** | All values encrypted with AES-256-CBC |
| 🧠 LLM reading file context | ✅ **Yes** | LLM sees only ciphertext; cannot decrypt |
| 💾 Cold boot / memory dump | ✅ **Partial** | Bytearray zeroing reduces exposure window significantly |
| 🔁 Heap inspection after password use | ✅ **Strong** | Buffer overwritten and garbage collected |
| 🕵️ Password string interning | ✅ **Mitigated** | Long passwords (>20 chars) avoid CPython's small-string cache |
| 🔓 Brute force attacks | ✅ **Mitigated** | PBKDF2 with 100K iterations slows dictionary attacks |

### Limitations

- **Password length**: Passwords ≤ 20 characters may be interned by CPython, leaving a cached copy in memory. Use passwords longer than 20 characters for maximum safety.
- **Process memory**: While the password is in use, it exists somewhere in process memory. No pure-Python solution can fully prevent this.
- **Swap / Hibernation**: The OS may write process memory to disk. Use full-disk encryption for complete protection.

---

## 🧪 Testing

A comprehensive test suite is included:

```bash
python test_sec_env.py
```

### 14 Test Functions

| Test | Validates |
|------|-----------|
| `test_process_str_password` | Encryption with string password; preserves formatting |
| `test_process_bytearray_password` | Encryption with bytearray password |
| `test_load` | Load decrypts all values into os.environ |
| `test_load_bytearray_password` | Load with bytearray; verifies password is wiped |
| `test_restore` | Full cycle restore — encrypt then decrypt back to original plaintext |
| `test_restore_mixed` | Restore with both encrypted and plaintext values |
| `test_unlock` | Unlocker decrypts individual keys; KeyError handling |
| `test_unlock_bytearray` | Unlocker copies bytearray (doesn't wipe original) |
| `test_key` | Single-key access; custom env_path support |
| `test_key_bytearray_password` | Key function wipes passed bytearray |
| `test_error_handling` | FileNotFoundError and wrong password handling |
| `test_round_trip` | Full cycle: process → load → key → unlocker |
| `test_load_mixed_content` | Handles both encrypted and plaintext values |
| `test_memory_wipe_detailed` | 5 sub-tests verifying all wipe behaviors |

---

## 📁 File Format

An encrypted `.env` file looks like:

```bash
# This comment is preserved
# Database configuration
DATABASE_URL=U2FsdGVkX18+ABC123def456...

# API Keys (encrypted)
API_KEY=U2FsdGVkX18+GHI789jkl012...

# Plaintext value (non-sensitive)
DEBUG=true
```

- **Encrypted values** are base64-encoded blobs containing salt (16) + IV (16) + ciphertext
- **Plaintext values** are passed through unchanged (e.g., `DEBUG=true`)
- **Comments**, **blank lines**, and **key ordering** are all preserved
- **Quoted values** are handled correctly (quotes are stripped before encryption)

---

## 📊 Comparison: SecureEnv vs. python-dotenv

| Feature | `python-dotenv` | SecureEnv |
|---------|-----------------|-----------|
| Secrets encrypted on disk | ❌ No | ✅ **Yes** |
| AES-256-CBC encryption | ❌ No | ✅ **Yes** |
| Restore .env to plaintext | ❌ No | ✅ **Yes** |
| Memory-safe password handling | ❌ N/A | ✅ **bytearray + zeroing** |
| `load_dotenv()` compatibility | ✅ Yes | ✅ **`sec_env.load()`** |
| Individual key decryption | ❌ No | ✅ **`unlock()` + `key()`** |
| Preserves comments/formatting | ✅ Yes | ✅ Yes |
| Self-contained | ✅ Yes | ✅ Yes |
| Password parameter order | N/A | `password` is first for `process()`, `load()`, and `restore()` |

---

## 📦 Project Structure

```
SecureEnv/
├── sec_env.py          # Main module (self-contained)
├── test_sec_env.py     # Comprehensive test suite
├── sec_env_docs.md     # Detailed module documentation
├── README.md           # This file
└── .gitignore
```

---

## 🤝 Contributing

Contributions are welcome! Please follow these guidelines:

1. **Security first** — Any changes to password handling or crypto must maintain or improve memory safety.
2. **Test coverage** — All new features must include tests.
3. **Self-contained** — Avoid adding external dependencies beyond `cryptography`.
4. **Documentation** — Update the README and inline docs as needed.

---

## 📄 License

[MIT License](LICENSE) — You are free to use, modify, and distribute this software.

---

## 🛡️ Disclaimer

While SecureEnv implements industry-standard encryption and memory-safety practices, **no software can guarantee absolute security** against a determined attacker with full system access. This module provides a significant defense-in-depth improvement over plaintext `.env` files, but should be used as part of a broader security strategy including:

- Full-disk encryption
- Least-privilege access controls
- Regular secret rotation
- Hardware Security Modules (HSMs) for production secrets

---

*Made with ❤️ to keep your secrets safe from prying eyes — whether human, machine, or neural network.*
