# KRYPTOS - Secure Password Manager

KRYPTOS is a modern password manager application that allows users to securely store and manage their passwords.

## Features

- 🔐 Secure data storage with AES-256 encryption
- 🔑 Single master password for all passwords
- ⏱️ Password expiration tracking
- 🔍 Password security analysis
- 🚨 Breached password checking
- 📋 Secure password generation
- 🎨 Modern and user-friendly interface
- 📱 Desktop application built with PyQt5

## Installation

1. Install Python 3.8 or higher
2. Clone the repository:
```bash
git clone https://github.com/username/KRYPTOS.git
cd KRYPTOS
```

3. Install required packages:
```bash
pip install -r requirements.txt
```

## Usage

1. Start the application:
```bash
python main.py
```

2. Create a master password on first run
3. Store your master password in a secure location
4. Add and manage your passwords

## Security Features

- AES-256 encryption
- Argon2 key derivation function
- HaveIBeenPwned API integration
- zxcvbn password strength analysis
- Automatic password expiration checking

## Requirements

- Python 3.8+
- PyQt5
- cryptography
- pykeepass
- colorama
- pyperclip
- requests
- zxcvbn-python
- pytz

## Security Warnings

- Store your master password in a secure location
- Regularly backup your `passwords.kdbx` file
- Change your passwords regularly
- Never share your master password

## Contributing

1. Fork this repository
2. Create a new feature branch (`git checkout -b new-feature`)
3. Commit your changes (`git commit -am 'New feature: Description'`)
4. Push to your branch (`git push origin new-feature`)
5. Create a Pull Request

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contact

For questions or suggestions, please open an issue on GitHub.

## Acknowledgments

- [KeePass](https://keepass.info/) - For encryption infrastructure
- [HaveIBeenPwned](https://haveibeenpwned.com/) - For password breach checking
- [zxcvbn](https://github.com/dropbox/zxcvbn) - For password strength analysis
