![Logo](app/static/img/pass1234.png)

# Pass1234

Pass1234 is a password-sharing application written in Python that utilizes the Flask micro web framework. It is designed to securely store and share passwords by employing AES-CBC 256-bit encryption to protect sensitive data, with PBKDF2 SHA-256 used to derive the encryption key for added security.

![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54)
![SQLite](https://img.shields.io/badge/sqlite-%2307405e.svg?style=for-the-badge&logo=sqlite&logoColor=white)
![Flask](https://img.shields.io/badge/flask-%23000.svg?style=for-the-badge&logo=flask&logoColor=white)
![Bulma](https://img.shields.io/badge/bulma-00D0B1?style=for-the-badge&logo=bulma&logoColor=white)

## :boom: Disclaimer

This password-sharing application is a **work in progress** and is intended **only for personal, local use on your desktop computer**. It has been developed using the Python programming language and the Flask web framework. However, please be aware that **I am not a security expert**, and this application has not undergone rigorous security audits or professional validation.

As such, this application **should not be used in a production environment** or deployed to the internet. It is designed to run locally on your own system, and the responsibility for ensuring the security of your passwords and personal data rests solely with you, the user. Please take appropriate precautions and consider seeking professional advice if needed.

Use this application at your own risk. **I disclaim any liability for any potential data breaches, security vulnerabilities, or loss of information that may result from its use**.

## :nut_and_bolt: Requirements

:white_check_mark: **Python 3.12+**

## 🔰 Start Here
Clone the repo
```bash
git clone https://github.com/radikaled/pass1234.git
cd pass1234
```
Create the Python virtual environment
```bash
python -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```
Export `SECRET_KEY` environment variable
```bash
export SECRET_KEY=`python -c "import secrets; print(secrets.token_hex(24))"`
```
Deploy the instance
```bash
gunicorn -w 4 'app:create_app()'
[2024-10-16 19:27:03 -0700] [812967] [INFO] Starting gunicorn 23.0.0
[2024-10-16 19:27:03 -0700] [812967] [INFO] Listening at: http://127.0.0.1:8000 (812967)
[2024-10-16 19:27:03 -0700] [812967] [INFO] Using worker: sync
...
```
Visit [http://127.0.0.1:8000](url) in your browser!

## Appendix

Some lessons learned from the excellent Bitwarden Security Whitepaper

- [https://bitwarden.com/help/kdf-algorithms/](url) :blue_book:
- [https://bitwarden.com/help/what-encryption-is-used/](url) :blue_book:
