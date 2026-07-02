# Chess-Based Secure Document Storage System

A Python GUI project for secure document storage using chess-derived AES encryption and hybrid RSA key sharing.

## What changed in the hybrid version

The old design required the sender to share the chess move sequence with the receiver. This version removes manual key sharing.

The new flow is:

```text
Document
→ Chess moves / chess phrase contribute to AES key generation
→ Document encrypted with AES-256-GCM
→ AES key encrypted with recipient's RSA public key
→ Receiver decrypts AES key with their private key
→ Receiver decrypts document
```

## Features

- User and admin login
- User registration
- Automatic RSA key pair generation for each user
- Private keys encrypted with the user's password
- Recipient-based document encryption
- AES-256-GCM document encryption
- RSA-OAEP-SHA256 AES key wrapping
- Chess move sequence or chess phrase as encryption entropy
- Stored `.chessvault` files
- Decrypted preview and download
- Admin log viewing and document deletion

## Installation

```bash
python3 -m pip install --user --no-cache-dir --timeout 300 -r requirements.txt
```

## Run

```bash
python3 main.py
```

## Default admin

```text
username: admin
password: admin123
role: admin
```

## Security note

The `.chessvault` file contains encrypted document data and an RSA-encrypted copy of the AES key for each recipient. It does not store the plaintext document or the plaintext AES key.

Runtime files such as databases, logs, stored documents, and encrypted vault files are intentionally excluded from GitHub.
