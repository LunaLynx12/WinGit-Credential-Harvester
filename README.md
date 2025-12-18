# Git Credential Harvester

> **Uncover Git credentials stored on Windows systems** - A penetration testing tool for authorized security assessments

[![Python](https://img.shields.io/badge/Python-3.7+-blue.svg)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey.svg)](https://www.microsoft.com/windows)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

## ⚠️ **DISCLAIMER**

**This tool is for authorized security testing and educational purposes ONLY.**

- Use on systems you own or have explicit written permission to test
- Unauthorized access to systems or credentials is **ILLEGAL**
- Use responsibly and ethically
- Authors are not responsible for misuse

## What It Does

Harvests and decrypts Git credentials from various Windows storage locations:

- **Windows Credential Manager** - Decrypts DPAPI-encrypted credentials
- **Git Config Files** - Extracts stored URLs, usernames, and emails
- **SSH Keys** - Locates private/public key pairs
- **`.git-credentials`** - Finds plaintext credential files
- **GitHub CLI** - Checks for stored OAuth tokens
- **Git Repositories** - Scans for remote URLs

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/LunaLynx12/WinGit-Credential-Harvester.git
cd WinGit-Credential-Harvester

# Create virtual environment
python -m venv venv
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Usage

```bash
python git_credential_harvester.py
```

**That's it!** The tool will automatically:
1. Scan all common Git credential storage locations
2. Decrypt Windows Credential Manager entries (DPAPI)
3. Display findings in a clean, color-coded format

## Example Output

```
======================================================================
RESULTS
======================================================================

[!] WINDOWS CREDENTIAL MANAGER
----------------------------------------------------------------------
  Source: Windows Credential Manager
  Encryption: Windows DPAPI
  [+] DECRYPTED CREDENTIALS:
    Username: your_username
    Password: gho_your_token_here

[!] GIT REPOSITORIES
----------------------------------------------------------------------
  Total: 3
  Path: C:\Users\You\Projects\MyRepo
    Remote: https://github.com/user/repo.git
```

## Features

- **DPAPI Decryption** - Automatically decrypts Windows Credential Manager entries
- **Multiple Sources** - Checks 7+ different credential storage locations
- **Clean Output** - Color-coded, easy-to-read results
- **Deduplication** - Removes duplicate credentials automatically
- **Silent Operation** - No errors if Git isn't installed

## Requirements

- Python 3.7+
- Windows OS
- `pywin32` (for DPAPI decryption)

## What Gets Checked

| Location | Description |
|----------|-------------|
| `~/.gitconfig` | Git global configuration |
| Windows Credential Manager | DPAPI-encrypted credentials |
| `~/.git-credentials` | Plaintext credential storage |
| `~/.ssh/` | SSH key pairs |
| `~/.config/gh/hosts.yml` | GitHub CLI tokens |
| Common project directories | Git repository remotes |


## Legal & Ethics

This tool is intended for:

- Authorized penetration testing
- Security research
- Educational purposes
- System administration on owned systems

**DO NOT** use this tool maliciously or without authorization.

## License

MIT License - See [LICENSE](LICENSE) file for details.

## Contributing

Contributions welcome! Please ensure all code follows ethical security practices.

## Show Your Support

If this tool helped you, give it a star on GitHub!


