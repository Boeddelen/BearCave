# BearCave

BearCave is a simple, terminal-based password manager with MFA, logging, and encryption. It is designed for Linux and uses OpenSSL for encryption and oathtool for TOTP-based multi-factor authentication.

## Features

- Secure password storage using AES-256 encryption
- Per-user vaults with strong password requirements
- Easily editable vault listings
- Optional TOTP MFA (requires oathtool)
- Logging of non-sensitive actions
- Minimal dependencies (OpenSSL, oathtool)
- Simple JSON-based vault format

## Requirements

- Bash
- OpenSSL
- oathtool (optional, for MFA)

## Usage

1. Clone the repository.
2. Run BearCave in your terminal:
3. Follow the interactive menu to create users, manage vaults, and enable MFA with any authenticator you want.

## License

BearCave is released under the [GNU General Public License v3.0](LICENSE). Contributions are welcome and free of charge.

---
Made by Frederik Flakne, 2025.
