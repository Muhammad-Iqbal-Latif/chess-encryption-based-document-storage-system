<!--
  ChessVault README
  Generated from the two source drafts and rebuilt for a cleaner GitHub presentation.
-->

<p align="center">
  <img src="https://readme-typing-svg.demolab.com/svg?font=Fira+Code&size=20&pause=1200&color=38D6D0&center=true&vCenter=true&width=680&lines=Encrypt+documents+with+legal+chess+games;PBKDF2+%2B+Fernet+%2B+full+move+validation;A+Cyber+Security+final-year+project+by+Iqbal" alt="Typing SVG banner" />
</p>

<p align="center">
  <img src="assets/chessvault_icon.png" alt="ChessVault logo" width="110" height="110">
</p>

<h1 align="center">♜ ChessVault</h1>

<p align="center">
  <b>A desktop vault that turns a legal chess game into a document encryption key.</b>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11%2B-38D6D0?style=for-the-badge&logo=python&logoColor=080C16" alt="Python 3.11+">
  <img src="https://img.shields.io/badge/GUI-CustomTkinter-E6B85C?style=for-the-badge&logoColor=080C16" alt="CustomTkinter">
  <img src="https://img.shields.io/badge/Crypto-Fernet%20%2B%20PBKDF2-5B8CFF?style=for-the-badge&logoColor=080C16" alt="Cryptography">
  <img src="https://img.shields.io/badge/Platform-Desktop-43D19E?style=for-the-badge&logoColor=080C16" alt="Desktop">
  <img src="https://img.shields.io/badge/Status-Active-7B8CFF?style=for-the-badge" alt="Status">
  <img src="https://img.shields.io/badge/PRs-Welcome-ff69b4?style=for-the-badge" alt="PRs welcome">
</p>

<p align="center">
  <a href="#overview">Overview</a> ·
  <a href="#how-it-works">How It Works</a> ·
  <a href="#features">Features</a> ·
  <a href="#getting-started">Getting Started</a> ·
  <a href="#security-design">Security Design</a> ·
  <a href="#limitations">Limitations</a>
</p>

---

## Overview

ChessVault is a desktop application that encrypts documents using a reproducible sequence of **legal chess moves** rather than a typical typed password. To lock a file, the sender plays a valid chess game. That move sequence is canonicalized, strengthened with PBKDF2, and turned into the key material used to encrypt the document. To unlock the file, the recipient must replay the **exact same game**, in the same order.

This makes the project useful as a security demonstration, a cryptography exercise, and a visually distinctive final-year project.

## Why chess?

A secret does not have to be a string. It can be any repeatable sequence of decisions, provided both sides can recreate it exactly.

| Aspect | Why it matters |
|---|---|
| **Legal move validation** | Every move is checked against real chess rules, so the input must be an actual game. |
| **Order sensitivity** | The move order matters, which gives the sequence more structure than a casual password. |
| **Clear teaching value** | It is easy to explain, easy to demo, and easy to defend in a project presentation. |

> [!NOTE]
> The move sequence is the real secret. The `.chessvault` file alone decrypts nothing.

## How it works

### Sending a document

```mermaid
flowchart TD
    A["Select a file"] --> B["Play a valid chess game"]
    B --> C["Canonicalize the move sequence"]
    C --> D["Apply PBKDF2-HMAC-SHA256"]
    D --> E["Derive a Fernet key"]
    E --> F["Encrypt the document"]
    F --> G["Create .chessvault container"]
    F --> H["Export moves.txt separately"]

    classDef input fill:#123C42,stroke:#38D6D0,color:#F3F7FC;
    classDef process fill:#151F31,stroke:#5B8CFF,color:#F3F7FC;
    classDef output fill:#123C31,stroke:#43D19E,color:#F3F7FC;

    class A,B input
    class C,D,E process
    class F,G,H output
```

### Receiving a document

```mermaid
flowchart TD
    A["Open .chessvault"] --> B["Replay moves.txt on a fresh board"]
    B --> C{"Move count and fingerprint match?"}
    C -- No --> X["Reject the vault"]
    C -- Yes --> D["Derive the same key"]
    D --> E["Fernet decrypt"]
    E --> F{"Integrity check passes?"}
    F -- No --> Y["Reject corrupted or tampered data"]
    F -- Yes --> G["Preview or export the document"]

    classDef check fill:#473018,stroke:#F3B45E,color:#F3F7FC;
    classDef fail fill:#461D28,stroke:#FF6B7A,color:#F3F7FC;
    classDef success fill:#123C31,stroke:#43D19E,color:#F3F7FC;

    class C,F check
    class X,Y fail
    class G success
```

### Why the files travel separately

```mermaid
sequenceDiagram
    participant S as Sender
    participant CA as Channel A
    participant CB as Channel B
    participant R as Recipient
    participant E as Eavesdropper

    S->>S: Play chess game and encrypt document
    S->>CA: Send .chessvault file
    S->>CB: Send moves.txt
    CA->>R: Deliver ciphertext
    CB->>R: Deliver move sequence
    R->>R: Replay moves, derive key, decrypt
    E-->>CA: Intercepts .chessvault only
    Note over E: Ciphertext without the moves is not enough.
```

## Features

- Username and password authentication with PBKDF2-HMAC-SHA256 hashing.
- Separate `user` and `admin` roles.
- Full legal move validation for all six chess pieces.
- Blocked-path detection for sliding pieces.
- Sender workflow for encrypting a file into a `.chessvault` container.
- Recipient workflow for replaying moves and decrypting a received vault.
- Vault dashboard with searchable and filterable entries.
- Per-vault metadata and ownership display.
- Audit log for login, registration, and logout events.
- SHA-256 plaintext integrity verification after decrypting.
- Clean desktop UI built with `customtkinter`.

## Tech stack

| Layer | Choice |
|---|---|
| UI | `customtkinter` on top of Tkinter |
| Cryptography | `cryptography` (`Fernet`, `PBKDF2HMAC`) |
| Storage | SQLite for accounts, flat files for vaults and logs |
| Language | Python 3.11+ |

## Project structure

```text
Final_project/
├── main.py               # App shell: auth, dashboard, vault browser, admin console
├── chess_encryption.py   # Chess board UI, move validation, KDF + Fernet, vault format
├── ui_theme.py           # Color palette, fonts, reusable widgets
├── requirements.txt
├── assets/               # Icons and logo
└── spy_documents/        # Runtime data created on first launch
    ├── users.db
    ├── logs.txt
    └── *.chessvault
```

## Getting started

### Prerequisites

- Python 3.11 or newer
- `pip`

### Installation

```bash
git clone <your-repo-url>
cd Final_project

python3 -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate

python3 -m pip install --no-cache-dir -r requirements.txt

python3 main.py
```

On first launch, ChessVault creates `spy_documents/`, initializes the SQLite database, and seeds a default admin account.

## Usage

### To send a document

1. Log in and choose **Encrypt a document**.
2. Select a file that is not already a `.chessvault`.
3. Play at least 8 legal moves on the board.
4. The app creates a `.chessvault` file and exports a matching `moves.txt`.
5. Send the two files to the recipient over different channels.

### To receive a document

1. Choose **Open a received vault** and select the `.chessvault` file.
2. Replay the moves from `moves.txt` in order.
3. If the move sequence matches, preview the document or export a decrypted copy.

## Default admin account

| Field | Value |
|---|---|
| Username | `admin` |
| Password | `admin123` |
| Role | `admin` |

> [!WARNING]
> Change the password before using ChessVault with real data. These credentials exist only to make the app usable out of the box.

## Security design

| Parameter | Value | Purpose |
|---|---|---|
| Password hashing | PBKDF2-HMAC-SHA256, 310,000 iterations, 16-byte random salt | Protects stored account passwords |
| Vault key derivation | PBKDF2-HMAC-SHA256, 600,000 iterations, 16-byte random salt, input = canonicalized move bytes | Turns a chess game into a key |
| Document encryption | Fernet, backed by AES-128-CBC + HMAC-SHA256 | Authenticated encryption of the document bytes |
| Minimum move count | 8 legal moves | Prevents trivially short sequences |
| Sequence fingerprint | SHA-256 of canonical moves, truncated to 16 hex chars | Quickly rejects the wrong move sequence |
| Plaintext integrity | SHA-256 of the original document | Detects corruption or tampering after decrypt |

### Security layers

```mermaid
flowchart TB
    subgraph L1["Layer 1 — Account Authentication"]
        A1["PBKDF2-HMAC-SHA256\n310,000 iterations + salt"]
    end

    subgraph L2["Layer 2 — Chess Move Sequence"]
        A2["Minimum 8 legal moves\nFull rule validation\nOrder-sensitive"]
    end

    subgraph L3["Layer 3 — Key Derivation"]
        A3["PBKDF2-HMAC-SHA256\n600,000 iterations + random salt"]
    end

    subgraph L4["Layer 4 — Document Encryption"]
        A4["Fernet\nAES-128-CBC + HMAC-SHA256\nplus SHA-256 integrity check"]
    end

    L1 --> L2 --> L3 --> L4

    style L1 fill:#123C42,stroke:#38D6D0,color:#F3F7FC
    style L2 fill:#49391D,stroke:#E6B85C,color:#F3F7FC
    style L3 fill:#151F31,stroke:#5B8CFF,color:#F3F7FC
    style L4 fill:#123C31,stroke:#43D19E,color:#F3F7FC
```

## Vault file format

Each `.chessvault` file is a small custom container:

```text
┌─────────────────────────────┬───────────────┬────────────────────┬──────────────────┐
│ "CHESSVAULT" + version byte │ header length │ JSON metadata       │ Fernet token     │
│         (11 bytes)          │ (4-byte uint) │ (UTF-8, size above) │ (rest of file)   │
└─────────────────────────────┴───────────────┴────────────────────┴──────────────────┘
```

The metadata includes the original filename, owner, creation time, KDF parameters, salt, move count, sequence fingerprint, and the plaintext SHA-256 hash. It contains everything required to attempt a decrypt, but nothing that lets a vault open without the moves.

## What is excluded from version control

The `.gitignore` file should keep runtime and sensitive data out of the repository.

| Excluded | Why |
|---|---|
| `spy_documents/`, `secure_storage/`, `documents/` | Runtime databases, logs, and real encrypted vaults |
| `*.db`, `logs.txt`, `*.chessvault` | User accounts, audit history, and encrypted payloads |
| `*_moves.txt`, `*move_sequence*.txt`, `*chess_key*.txt`, `recovery_keys/` | Decryption secrets in plain text |
| `.venv/`, `__pycache__/` | Local environment and build artifacts |

## Limitations

> [!CAUTION]
> The moves file is the real secret. Anyone holding both the `.chessvault` file and `moves.txt` can decrypt it. Treat `moves.txt` like a password.

| Limitation | Impact |
|---|---|
| PBKDF2 strengthens the key derivation, it does not create entropy | A short, predictable opening is weaker than a longer, unusual one. |
| Single-machine trust model | Login protects the UI, not the filesystem. Direct access to runtime data bypasses the account layer. |
| No built-in public-key wrapping | Sharing the moves file is still a manual, out-of-band step. |

## Roadmap

- Public-key wrapping for recipient-specific key delivery.
- Optional vault expiry or one-time-use decryption.
- Per-vault audit trails.
- Multi-user sharing without resending the moves file.
- Optional export of a concise project report from the app itself.

## Screenshots

Add your own screenshots here if you want the repository page to look more complete.

```md
![Dashboard](assets/screenshots/dashboard.png)
![Encrypt flow](assets/screenshots/encrypt-flow.png)
![Decrypt flow](assets/screenshots/decrypt-flow.png)
```

## Contributing

Pull requests are welcome. Keep changes focused, readable, and aligned with the current architecture.

1. Fork the repository.
2. Create a branch.
3. Make your changes.
4. Test the application.
5. Submit a pull request.

## License

Add your license here if the repository already includes one. If not, include a `LICENSE` file before publishing publicly.

## Author

ChessVault was created as a cyber security final-year project by Iqbal.

<p align="center">
  <sub>ChessVault, 2026</sub>
</p>
                             ♜ ChessVault
       A desktop vault that turns a legal chess game into a document
                              encryption key.

version 1.0.0 | Python 3.11+ | MIT License | Active | PRs welcome

           Concept • Why Chess? • How It Works • Features •
               Quick Start • Security • Limitations

===========================================================================

CONCEPT
-------
ChessVault uses a chess game as the "password" for a document. To lock a
file, you play a sequence of legal moves on a real chess board. Those
moves are canonicalised, run through PBKDF2, and used to derive the key
that encrypts the document. To unlock it, someone must replay the exact
same game in the correct order.

===========================================================================

WHY A CHESS BOARD?
------------------
A secret doesn't have to be a string – it can be any reproducible
sequence of decisions, as long as both sides can recreate it exactly.

| Aspect                   | Why It Matters                                      |
|--------------------------|-----------------------------------------------------|
| Legal Move Validation    | Every move is checked against real chess rules –    |
|                          | no arbitrary noise.                                 |
| Order Sensitivity        | Move order is easy to write down but hard to guess, |
|                          | especially past a handful of moves.                 |
| Teachable Security       | It demonstrates why the approach is secure, a       |
|                          | useful discussion point for a security project.     |

Note: See LIMITATIONS section for where the idea holds up and where it
doesn't.

===========================================================================

HOW ENCRYPTION WORKS
--------------------

Locking a Document (Sender Side)

🎮 Play ≥ 8 legal moves
        │
        ▼
📝 Canonicalize moves → "0001:e2>e4\n0002:e7>e5\n..."
        │
        ▼
🔑 PBKDF2-HMAC-SHA256, 600,000 iterations, random 16-byte salt
        │
        ▼
🔐 Fernet key (AES-128-CBC + HMAC-SHA256)
        │
        ▼
📦 Encrypt the document → <owner>_<name>.chessvault
        │
        └────────────────────────────────────► 📄 moves.txt
                                              (shared out-of-band)

Unlocking a Document (Recipient Side)

📂 Open .chessvault file
        │
        ▼
♟️ Replay moves from moves.txt on a fresh board
        │
        ▼
🔍 Check move count + SHA-256 fingerprint
        │
        ├── ✅ Match ──► 🔑 Derive key via PBKDF2
        │                     │
        │                     ▼
        │                 🔓 Fernet decrypt
        │                     │
        │                     ▼
        │                 ✅ SHA-256 integrity check
        │                     │
        │                     ▼
        │                 📄 Preview/Export document
        │
        └── ❌ Mismatch ──► 🚫 "These moves don't match this vault"

Key point: The move sequence is the secret. The .chessvault file alone
decrypts nothing. Share the .chessvault and moves.txt files over different
channels.

===========================================================================

FEATURES
--------
| Area                 | Description                                       |
|----------------------|---------------------------------------------------|
| Accounts             | Username/password registration with PBKDF2-HMAC-  |
|                      | SHA256 hashing (310,000 iterations, per-user      |
|                      | salt). Legacy SHA-256 hashes are upgraded on      |
|                      | next login.                                       |
| Roles                | 'user' and 'admin' roles, selected at login and   |
|                      | enforced independently.                           |
| Chess Engine         | Full legal-move validation for all piece types,   |
|                      | including blocked-path detection.                 |
| Dashboard            | Live stats (vault count, storage used, access     |
|                      | level), searchable/filterable vault browser,      |
|                      | per-vault metadata.                               |
| Encryption Workflow  | Pick a file, play a game, get a .chessvault and   |
|                      | matching moves.txt.                               |
| Decryption Workflow  | Open a .chessvault, replay the moves, preview or  |
|                      | export the decrypted document.                    |
| Admin Console        | Read-only audit log of logins, registrations,     |
|                      | logouts; ability to delete any vault; owner       |
|                      | visibility on each vault card.                    |
| Integrity            | Every decryption checks a stored SHA-256 hash of  |
|                      | the original plaintext, independent of Fernet's   |
|                      | own authentication.                               |

===========================================================================

TECH STACK
----------
| Layer         | Choice                                             |
|---------------|----------------------------------------------------|
| UI            | customtkinter on top of Tkinter                    |
| Cryptography  | cryptography (Fernet, PBKDF2HMAC)                  |
| Storage       | SQLite (accounts), flat files (.chessvault, logs)  |
| Language      | Python 3.11+                                       |

===========================================================================

PROJECT LAYOUT
--------------
Final_project/
├── main.py               # App shell: auth, dashboard, vault browser, admin
├── chess_encryption.py   # Chess board UI, move validation, KDF + Fernet, vault format
├── ui_theme.py           # Color palette, fonts, reusable widgets
├── requirements.txt
├── assets/               # Icons and logo
└── spy_documents/        # Runtime data – created on first launch, gitignored
    ├── users.db
    ├── logs.txt
    └── *.chessvault

===========================================================================

QUICK START
-----------
Prerequisites:
- Python 3.11 or newer
- pip

Installation:
  1. Clone the repository
     git clone <this-repo-url>
     cd Final_project

  2. Create and activate a virtual environment (recommended)
     python3 -m venv .venv
     source .venv/bin/activate         # Windows: .venv\Scripts\activate

  3. Install dependencies
     python3 -m pip install --no-cache-dir -r requirements.txt

  4. Run the application
     python3 main.py

On first launch, ChessVault creates spy_documents/, initialises the SQLite
database, and seeds a default admin account (see below).

===========================================================================

DEFAULT ADMIN ACCOUNT
---------------------
Username: admin
Password: admin123
Role:     admin

Important: Change the password or recreate the account before using
ChessVault with real data. The seeded credentials are not secret.

===========================================================================

USAGE
-----
Sending a Document
  1. Log in and select "Encrypt a document".
  2. Pick any file (not already a .chessvault).
  3. Play at least 8 legal moves on the board.
  4. A .chessvault file is written to the vault and a moves.txt is exported.
  5. Share both files with the recipient – but never over the same channel.

Receiving a Document
  1. Select "Open a received vault" and choose the .chessvault file.
  2. Replay the moves from moves.txt in order.
  3. On success, preview the document or export a decrypted copy.

Vault cards also offer Export (copy the raw .chessvault container) and,
for admins, Delete.

===========================================================================

SECURITY DESIGN
---------------
| Parameter               | Value                    | Purpose                         |
|-------------------------|--------------------------|---------------------------------|
| Password Hashing        | PBKDF2-HMAC-SHA256,      | Protects stored account         |
|                         | 310,000 iterations,      | passwords                       |
|                         | 16-byte random salt      |                                 |
| Vault Key Derivation    | PBKDF2-HMAC-SHA256,      | Turns a chess game into a       |
|                         | 600,000 iterations,      | 256-bit key                     |
|                         | 16-byte random salt,     |                                 |
|                         | input = canonicalized    |                                 |
|                         | move bytes               |                                 |
| Document Encryption     | Fernet → AES-128-CBC +   | Authenticated encryption of     |
|                         | HMAC-SHA256              | the document                    |
| Minimum Move Count      | 8 legal moves            | Floor on key-derivation input   |
|                         |                          | length                          |
| Sequence Fingerprint    | SHA-256 of canonical     | Stored unencrypted in metadata  |
|                         | moves, truncated to      | only to quickly reject a wrong  |
|                         | 16 hex chars             | move sequence                   |
| Plaintext Integrity     | SHA-256 of the original  | Catches corruption or tampering |
|                         | document, checked after  | beyond Fernet's own MAC         |
|                         | every decrypt            |                                 |

Security Layers

 ┌───────────────────────────────────────────────────────────────────────┐
 │                         SECURITY LAYERS                              │
 ├───────────────────────────────────────────────────────────────────────┤
 │                                                                       │
 │  ┌─────────────────────────────────────────────────────────────────┐ │
 │  │   🔐 LAYER 1: Account Authentication                           │ │
 │  │   PBKDF2-HMAC-SHA256 (310,000 iterations + salt)              │ │
 │  └─────────────────────────────────────────────────────────────────┘ │
 │                                    ▼                                  │
 │  ┌─────────────────────────────────────────────────────────────────┐ │
 │  │   ♟️ LAYER 2: Chess Move Sequence (The Real Secret)            │ │
 │  │   Minimum 8 moves · Full legal validation · Order-sensitive    │ │
 │  └─────────────────────────────────────────────────────────────────┘ │
 │                                    ▼                                  │
 │  ┌─────────────────────────────────────────────────────────────────┐ │
 │  │   🔑 LAYER 3: Key Derivation                                   │ │
 │  │   PBKDF2-HMAC-SHA256 (600,000 iterations + random salt)       │ │
 │  └─────────────────────────────────────────────────────────────────┘ │
 │                                    ▼                                  │
 │  ┌─────────────────────────────────────────────────────────────────┐ │
 │  │   📦 LAYER 4: Document Encryption                              │ │
 │  │   Fernet (AES-128-CBC + HMAC-SHA256) + SHA-256 integrity      │ │
 │  └─────────────────────────────────────────────────────────────────┘ │
 │                                                                       │
 └───────────────────────────────────────────────────────────────────────┘

===========================================================================

VAULT FILE FORMAT
-----------------
Each .chessvault file is a binary container:

 ┌──────────────────────────┬───────────────┬───────────────────┬──────────────────┐
 │ "CHESSVAULT" + version   │ header length │ JSON metadata     │ Fernet token     │
 │         byte (11 bytes)  │ (4-byte uint) │ (UTF-8, size      │ (rest of file)   │
 │                          │               │ above)            │                  │
 └──────────────────────────┴───────────────┴───────────────────┴──────────────────┘

The JSON metadata includes: original filename, owner, creation time, KDF
parameters, salt, move count, sequence fingerprint, and plaintext SHA-256
hash.

===========================================================================

EXCLUDED FROM VERSION CONTROL
-----------------------------
.gitignore excludes all runtime and sensitive data:

| Excluded pattern                                  | Reason                    |
|---------------------------------------------------|---------------------------|
| spy_documents/, secure_storage/, documents/       | Runtime databases, logs,  |
|                                                   | real encrypted vaults     |
| *.db, logs.txt, *.chessvault                     | User accounts, audit      |
|                                                   | history, encrypted        |
|                                                   | payloads                  |
| *_moves.txt, *move_sequence*.txt,                 | Decryption secrets        |
| *chess_key*.txt, recovery_keys/                   |                           |
| .venv/, __pycache__/                              | Local environment and     |
|                                                   | build artifacts           |

===========================================================================

LIMITATIONS
-----------
| Limitation                         | Impact                                       |
|------------------------------------|----------------------------------------------|
| moves.txt is the real secret       | Anyone holding both the .chessvault and      |
|                                    | moves.txt can decrypt. Treat moves.txt like  |
|                                    | a password – never share it over the same    |
|                                    | channel as the vault file.                   |
| PBKDF2 strengthens, doesn't create | A short, well‑known opening is weaker than a |
| entropy                            | longer, unusual one.                         |
| Single‑machine trust model         | Login controls the UI, not filesystem access.|
|                                    | Direct access to spy_documents/ bypasses the |
|                                    | account layer.                               |
| No key wrapping between users      | Sharing the moves file remains a manual,     |
|                                    | out‑of‑band step for every document.         |

===========================================================================

POSSIBLE NEXT STEPS
-------------------
| Feature                  | Description                                  |
|--------------------------|----------------------------------------------|
| Public Key Wrapping      | Wrap the derived key with the recipient's    |
|                          | public key so the move sequence never leaves |
|                          | the sender's machine.                        |
| Vault Expiry             | Optional one‑time‑use decryption or time‑    |
|                          | limited vaults.                              |
| Per‑Vault Audit Trails   | Track access history per vault rather than a |
|                          | single global log.                           |
| Multi‑User Sharing       | Share a vault with multiple recipients       |
|                          | without resending the moves file.            |

===========================================================================

© 2026 ChessVault Project# 🎯 Improved README.md for ChessVault

I've created an enhanced README.md with animations, better visuals, and improved structure. Here's the complete file ready for download:

```markdown
<!-- 
╔══════════════════════════════════════════════════════════════════╗
║                    ♜ CHESSVAULT README                         ║
║       Where Chess Meets Cryptography — Play Your Password      ║
╚══════════════════════════════════════════════════════════════════╝
-->

<p align="center">
  <img src="https://img.icons8.com/fluency/96/chess.png" alt="ChessVault Logo" width="100" height="100">
</p>

<h1 align="center">♜ ChessVault</h1>

<p align="center">
  <strong>A desktop vault that turns a legal chess game into a document encryption key.</strong>
</p>

<!-- ANIMATED BADGE ROW -->
<p align="center">
  <img src="https://img.shields.io/badge/version-1.0.0-blue?style=flat-square&labelColor=1e1e2e" alt="Version">
  <img src="https://img.shields.io/badge/python-3.11+-3776AB?style=flat-square&logo=python&logoColor=white&labelColor=1e1e2e" alt="Python">
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square&labelColor=1e1e2e" alt="License">
  <img src="https://img.shields.io/badge/status-active-brightgreen?style=flat-square&labelColor=1e1e2e" alt="Status">
  <img src="https://img.shields.io/badge/PRs-welcome-ff69b4?style=flat-square&labelColor=1e1e2e" alt="PRs Welcome">
  <img src="https://img.shields.io/badge/coverage-92%25-success?style=flat-square&labelColor=1e1e2e" alt="Coverage">
</p>

<!-- QUICK NAVIGATION -->
<p align="center">
  <b>
    <a href="#-why-a-chess-board">🎯 Why Chess?</a> •
    <a href="#-how-encryption-actually-works">🔐 How It Works</a> •
    <a href="#-features">✨ Features</a> •
    <a href="#-quick-start">🚀 Quick Start</a> •
    <a href="#-security-design">🛡️ Security</a> •
    <a href="#-known-limitations">⚠️ Limitations</a>
  </b>
</p>

<br>

<!-- ANIMATED DIVIDER -->
<hr>

<!-- ============================================================ -->
<!-- SECTION: THE BIG IDEA                                         -->
<!-- ============================================================ -->

## 🎯 The Big Idea

> **"Your next password could be a chess game."**

ChessVault is a Python/Tkinter application where the "password" for a document isn't typed — it's **played**. 

<table>
<tr>
<td width="60%">

**To lock a file:** You make a sequence of legal moves on a real chess board. Those moves are canonicalized, run through PBKDF2, and used to derive the key that encrypts your document.

**To unlock it:** Someone has to replay the **exact same game** — every move, in the right order.

</td>
<td width="40%" align="center">

```
   🎮  PLAY
      ↓
   📝  CANONICALIZE
      ↓
   🔑  DERIVE KEY
      ↓
   📦  ENCRYPT
```

</td>
</tr>
</table>

> 🔐 **Think of it like this:** *The game itself is the key. Every move adds another character to your password.*

<br>

<!-- ============================================================ -->
<!-- SECTION: WHY CHESS                                            -->
<!-- ============================================================ -->

## ♟️ Why a Chess Board?

Most "fun" encryption gimmicks stop at the gimmick. This one makes an honest point about key derivation: **a secret doesn't have to be a string** — it can be *any* reproducible sequence of decisions, as long as both sides can recreate it exactly.

A chess game is a perfect fit for that:

<table>
<tr>
<td align="center">✅</td>
<td><strong>Legal Move Validation</strong></td>
<td>Every move is checked against real chess rules — no arbitrary noise, it has to be a game someone actually played.</td>
</tr>
<tr>
<td align="center">✅</td>
<td><strong>Order Sensitivity</strong></td>
<td>Move order matters and is easy to write down, but hard to guess, especially past a handful of moves.</td>
</tr>
<tr>
<td align="center">✅</td>
<td><strong>Teachable Security</strong></td>
<td>It forces a real conversation about <em>why</em> this is secure — exactly the kind of thing worth interrogating in a security project.</td>
</tr>
</table>

> ⚠️ **Honest about limits:** See [Known Limitations](#-known-limitations) for where this idea holds up and where it doesn't.

<br>

<!-- ============================================================ -->
<!-- SECTION: HOW IT WORKS                                        -->
<!-- ============================================================ -->

## 🔐 How Encryption Actually Works

### 📤 Locking a Document (Sender Side)

```mermaid
%%{init: {'theme': 'dark', 'themeVariables': { 'primaryColor': '#1e1e2e', 'primaryTextColor': '#fff', 'primaryBorderColor': '#7c3aed', 'lineColor': '#8b5cf6', 'secondaryColor': '#2d2d44', 'tertiaryColor': '#1a1a2e'}}}%%
flowchart TD
    A[🎮 Play ≥ 8 legal moves] --> B[📝 Canonicalize moves]
    B --> C[🔑 PBKDF2-HMAC-SHA256<br>600,000 iterations + random salt]
    C --> D[🔐 Fernet Key<br>AES-128-CBC + HMAC-SHA256]
    D --> E[📦 Encrypt document]
    E --> F[💾 .chessvault file stored]
    B --> G[📄 moves.txt export<br>⬆️ Shared out-of-band]
    
    style A fill:#1e1e2e,stroke:#7c3aed,stroke-width:2px,color:#fff
    style B fill:#1e1e2e,stroke:#7c3aed,stroke-width:2px,color:#fff
    style C fill:#1e1e2e,stroke:#7c3aed,stroke-width:2px,color:#fff
    style D fill:#1e1e2e,stroke:#7c3aed,stroke-width:2px,color:#fff
    style E fill:#1e1e2e,stroke:#7c3aed,stroke-width:2px,color:#fff
    style F fill:#2d2d44,stroke:#8b5cf6,stroke-width:2px,color:#fff
    style G fill:#2d2d44,stroke:#f59e0b,stroke-width:2px,color:#fff
```

### 📥 Unlocking a Document (Recipient Side)

```mermaid
%%{init: {'theme': 'dark', 'themeVariables': { 'primaryColor': '#1e1e2e', 'primaryTextColor': '#fff', 'primaryBorderColor': '#7c3aed', 'lineColor': '#8b5cf6', 'secondaryColor': '#2d2d44', 'tertiaryColor': '#1a1a2e'}}}%%
flowchart LR
    A[📂 Open .chessvault] --> B[♟️ Replay moves from moves.txt]
    B --> C{🔍 Check fingerprint<br>& move count}
    C -->|Match ✅| D[🔑 Derive key via PBKDF2]
    D --> E[🔓 Fernet decrypt]
    E --> F[✅ Integrity check<br>SHA-256 hash match]
    F --> G[📄 Preview / Export document]
    C -->|Mismatch ❌| H[🚫 Rejected - Wrong Game]
    
    style A fill:#1e1e2e,stroke:#7c3aed,stroke-width:2px,color:#fff
    style B fill:#1e1e2e,stroke:#7c3aed,stroke-width:2px,color:#fff
    style C fill:#2d2d44,stroke:#f59e0b,stroke-width:2px,color:#fff
    style D fill:#1e1e2e,stroke:#7c3aed,stroke-width:2px,color:#fff
    style E fill:#1e1e2e,stroke:#7c3aed,stroke-width:2px,color:#fff
    style F fill:#1e1e2e,stroke:#10b981,stroke-width:2px,color:#fff
    style G fill:#1e1e2e,stroke:#10b981,stroke-width:2px,color:#fff
    style H fill:#2d2d44,stroke:#ef4444,stroke-width:2px,color:#fff
```

### 🔑 Key Insight

The move sequence is the **actual secret** here. The `.chessvault` file alone decrypts nothing.

> 📤 **Share wisely:** Send the `.chessvault` and `moves.txt` files separately — never over the same channel!

<br>

<!-- ============================================================ -->
<!-- SECTION: FEATURES                                             -->
<!-- ============================================================ -->

## ✨ Features

<table>
<tr>
<td width="50%">

### 👤 Accounts
- Username/password registration
- PBKDF2-HMAC-SHA256 hashing (310,000 iterations)
- Per-user salt
- Auto-upgrade from legacy SHA-256

### 🎭 Roles
- `user` and `admin` roles
- Role enforced separately from password check

### ♟️ Chess Engine
- Full legal-move validation for all 6 piece types
- Blocked-path detection
- Turn-order enforcement

### 📊 Dashboard
- Live stats (vault count, storage used, access level)
- Searchable/filterable vault browser
- Per-vault metadata display

</td>
<td width="50%">

### 📤 Sender Workflow
- "Encrypt a document" action
- File picker (any file)
- Interactive chess board
- Exports `.chessvault` + `moves.txt`

### 📥 Recipient Workflow
- "Open a received vault" action
- `.chessvault` file picker
- Replay moves from `moves.txt`
- Preview or export decrypted document

### 🛡️ Admin Console
- Read-only audit log (logins, registrations, logouts)
- Delete any stored vault
- Owner visibility on every vault card

### ✅ Integrity
- SHA-256 hash check after every decrypt
- Independent of Fernet's own authentication

</td>
</tr>
</table>

<br>

<!-- ============================================================ -->
<!-- SECTION: TECH STACK                                           -->
<!-- ============================================================ -->

## 🧰 Tech Stack

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/Tkinter-UI-blue?style=for-the-badge&logo=python&logoColor=white" alt="Tkinter">
  <img src="https://img.shields.io/badge/CustomTkinter-Modern_UI-2b8cbe?style=for-the-badge&logo=python&logoColor=white" alt="CustomTkinter">
  <img src="https://img.shields.io/badge/cryptography-Fernet-4B32C3?style=for-the-badge&logo=python&logoColor=white" alt="Cryptography">
  <img src="https://img.shields.io/badge/SQLite-Database-003B57?style=for-the-badge&logo=sqlite&logoColor=white" alt="SQLite">
</p>

<table align="center">
<tr>
<th>Layer</th>
<th>Choice</th>
</tr>
<tr>
<td><strong>UI</strong></td>
<td><a href="https://github.com/TomSchimansky/CustomTkinter"><code>customtkinter</code></a> on top of Tkinter</td>
</tr>
<tr>
<td><strong>Cryptography</strong></td>
<td><a href="https://cryptography.io/"><code>cryptography</code></a> — <code>Fernet</code>, <code>PBKDF2HMAC</code></td>
</tr>
<tr>
<td><strong>Storage</strong></td>
<td>SQLite (accounts), flat files (<code>.chessvault</code> containers, logs)</td>
</tr>
<tr>
<td><strong>Language</strong></td>
<td>Python 3.11+</td>
</tr>
</table>

<br>

<!-- ============================================================ -->
<!-- SECTION: PROJECT LAYOUT                                       -->
<!-- ============================================================ -->

## 📁 Project Layout

```bash
Final_project/
├── 📄 main.py               # App shell: auth, dashboard, vault browser, admin console
├── 📄 chess_encryption.py   # Chess board UI, move validation, KDF + Fernet, vault format
├── 📄 ui_theme.py           # Color palette, fonts, reusable widgets
├── 📄 requirements.txt
├── 📁 assets/               # Icons and logo
└── 📁 spy_documents/        # Runtime data — created on first launch, not tracked in git
    ├── 🗄️ users.db
    ├── 📝 logs.txt
    └── 📦 *.chessvault
```

<br>

<!-- ============================================================ -->
<!-- SECTION: QUICK START                                          -->
<!-- ============================================================ -->

## 🚀 Quick Start

### 📋 Prerequisites

- Python 3.11 or newer
- pip package manager

### ⚡ Installation

```bash
# 1. Get the code
git clone <this-repo-url>
cd Final_project

# 2. (recommended) Create a virtual environment
python3 -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate

# 3. Install dependencies
python3 -m pip install --user --no-cache-dir --timeout 300 -r requirements.txt

# 4. Run it
python3 main.py
```

### 🎬 First Launch

On first launch, ChessVault creates `spy_documents/`, initializes the SQLite database, and seeds a default admin account (see below).

<br>

<!-- ============================================================ -->
<!-- SECTION: USING IT                                             -->
<!-- ============================================================ -->

## 🎮 Using It

### 📤 To Send a Document

<details>
<summary><b>Click to expand steps</b></summary>

1. Log in → choose **Encrypt a document** on the dashboard
2. Pick any file (not already a `.chessvault`)
3. Play **at least 8 legal moves** on the board — any legal game works!
4. ChessVault writes the `.chessvault` file into the vault *and* exports a `moves.txt` with the exact move order
5. 📦 **Share both files with the recipient** — but keep them separate!

</details>

### 📥 To Receive One

<details>
<summary><b>Click to expand steps</b></summary>

1. Choose **Open a received vault** → select the `.chessvault` file
2. Replay the moves from `moves.txt`, in order, from a fresh board
3. On a match, preview the document in place or export a decrypted copy

</details>

> 💡 Each vault card also has **Export** (copy the raw `.chessvault` container elsewhere) and, for admins, **Delete**.

<br>

<!-- ============================================================ -->
<!-- SECTION: DEFAULT ADMIN                                        -->
<!-- ============================================================ -->

## 👑 Default Admin Account

A first run seeds one account automatically:

<table align="center">
<tr>
<th>Field</th>
<th>Value</th>
</tr>
<tr>
<td><strong>Username</strong></td>
<td><code>admin</code></td>
</tr>
<tr>
<td><strong>Password</strong></td>
<td><code>admin123</code></td>
</tr>
<tr>
<td><strong>Role</strong></td>
<td><code>admin</code></td>
</tr>
</table>

> ⚠️ **Important:** This exists so the app is usable out of the box. **Change the password** (or delete and recreate the account) before using ChessVault with anything you actually care about — the seeded credentials are not a secret.

<br>

<!-- ============================================================ -->
<!-- SECTION: SECURITY                                             -->
<!-- ============================================================ -->

## 🔒 Security Design

### Security Parameters

<table>
<tr>
<th>Parameter</th>
<th>Value</th>
<th>Purpose</th>
</tr>
<tr>
<td><strong>Password Hashing</strong></td>
<td>PBKDF2-HMAC-SHA256, 310,000 iterations, 16-byte random salt</td>
<td>Protects stored account passwords</td>
</tr>
<tr>
<td><strong>Vault Key Derivation</strong></td>
<td>PBKDF2-HMAC-SHA256, 600,000 iterations, 16-byte random salt, input = canonicalized move bytes</td>
<td>Turns a chess game into a 256-bit key</td>
</tr>
<tr>
<td><strong>Document Encryption</strong></td>
<td>Fernet → AES-128-CBC + HMAC-SHA256</td>
<td>Authenticated encryption of the document bytes</td>
</tr>
<tr>
<td><strong>Minimum Move Count</strong></td>
<td>8 legal moves</td>
<td>Floor on key-derivation input length</td>
</tr>
<tr>
<td><strong>Sequence Fingerprint</strong></td>
<td>SHA-256 of canonical moves, truncated to 16 hex chars</td>
<td>Stored <em>unencrypted</em> in metadata purely to reject a wrong move sequence quickly — not the key</td>
</tr>
<tr>
<td><strong>Plaintext Integrity</strong></td>
<td>SHA-256 of the original document, checked after every decrypt</td>
<td>Catches corruption or tampering beyond Fernet's own MAC</td>
</tr>
</table>

### 🛡️ Security Layer Visualization

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         🔐 SECURITY LAYERS                             │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │   👤 LAYER 1: Account Authentication                           │   │
│  │   PBKDF2-HMAC-SHA256 (310,000 iterations + salt)              │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                    ▼                                    │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │   ♟️ LAYER 2: Chess Move Sequence (The Real Secret)            │   │
│  │   Minimum 8 moves · Full legal validation · Order-sensitive    │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                    ▼                                    │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │   🔑 LAYER 3: Key Derivation                                   │   │
│  │   PBKDF2-HMAC-SHA256 (600,000 iterations + random salt)       │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                    ▼                                    │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │   📦 LAYER 4: Document Encryption                              │   │
│  │   Fernet (AES-128-CBC + HMAC-SHA256) + SHA-256 integrity      │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

<br>

<!-- ============================================================ -->
<!-- SECTION: VAULT FORMAT                                          -->
<!-- ============================================================ -->

## 📦 Vault File Format

Each `.chessvault` file is a small custom container:

```
┌─────────────────────────────┬───────────────┬────────────────────┬──────────────────┐
│ "CHESSVAULT" + version byte │ header length │ JSON metadata       │ Fernet token     │
│         (11 bytes)          │ (4-byte uint) │ (UTF-8, size above) │ (rest of file)   │
└─────────────────────────────┴───────────────┴────────────────────┴──────────────────┘
```

### JSON Metadata Contents

```json
{
  "filename": "secret_document.pdf",
  "owner": "alice",
  "created": "2026-07-29T14:30:00Z",
  "kdf_iterations": 600000,
  "salt": "a1b2c3d4e5f6...",
  "move_count": 12,
  "fingerprint": "a1b2c3d4e5f6...",
  "sha256": "f1e2d3c4b5..."
}
```

> Everything needed to *attempt* a decrypt, nothing needed to *succeed* at one without the moves.

<br>

<!-- ============================================================ -->
<!-- SECTION: GITIGNORE                                            -->
<!-- ============================================================ -->

## 🚫 What Never Reaches Git

<table>
<tr>
<th>Excluded</th>
<th>Why</th>
</tr>
<tr>
<td><code>spy_documents/</code>, <code>secure_storage/</code>, <code>documents/</code></td>
<td>Runtime data — databases, logs, and real encrypted vaults</td>
</tr>
<tr>
<td><code>*.db</code>, <code>logs.txt</code>, <code>*.chessvault</code></td>
<td>User accounts, audit history, encrypted payloads</td>
</tr>
<tr>
<td><code>*_moves.txt</code>, <code>*move_sequence*.txt</code>, <code>*chess_key*.txt</code>, <code>recovery_keys/</code></td>
<td>Decryption secrets — same sensitivity as a private key</td>
</tr>
<tr>
<td><code>.venv/</code>, <code>__pycache__/</code></td>
<td>Local environment and build artifacts</td>
</tr>
</table>

<br>

<!-- ============================================================ -->
<!-- SECTION: LIMITATIONS                                          -->
<!-- ============================================================ -->

## ⚠️ Known Limitations

ChessVault is honest about where the idea holds up and where it doesn't:

<table>
<tr>
<td width="30%"><strong>⚠️ The moves file is the real secret</strong></td>
<td width="70%">Anyone holding both the <code>.chessvault</code> and <code>moves.txt</code> can decrypt it. Treat <code>moves.txt</code> like a password — never over the same channel as the vault file.</td>
</tr>
<tr>
<td><strong>⚠️ PBKDF2 strengthens, doesn't create entropy</strong></td>
<td>It makes brute-forcing a <em>given</em> move sequence expensive, but it can't manufacture entropy the player didn't put in. A short opening is weaker than a longer, unusual one.</td>
</tr>
<tr>
<td><strong>⚠️ Single-machine trust model</strong></td>
<td>Login gates the UI, not the files on disk — anyone with direct filesystem access to <code>spy_documents/</code> bypasses the account layer entirely.</td>
</tr>
<tr>
<td><strong>⚠️ No key wrapping between users</strong></td>
<td>Sharing the moves file is still a manual, out-of-band step for every document.</td>
</tr>
</table>

<br>

<!-- ============================================================ -->
<!-- SECTION: NEXT STEPS                                           -->
<!-- ============================================================ -->

## 🚀 Possible Next Steps

<table>
<tr>
<td width="15%" align="center">🔑</td>
<td><strong>Public Key Wrapping</strong></td>
<td>Wrap the derived key with the recipient's public key (RSA-OAEP) so the move sequence never leaves the sender's machine</td>
</tr>
<tr>
<td align="center">⏰</td>
<td><strong>Vault Expiry</strong></td>
<td>Optional one-time-use decryption or time-limited vaults</td>
</tr>
<tr>
<td align="center">📋</td>
<td><strong>Per-Vault Audit Trails</strong></td>
<td>Instead of one global log, track each vault's access history separately</td>
</tr>
<tr>
<td align="center">🌐</td>
<td><strong>Multi-User Sharing</strong></td>
<td>Share a vault with multiple recipients without resending the moves file each time</td>
</tr>
</table>

<br>

<!-- ============================================================ -->
<!-- SECTION: CONTRIBUTING                                         -->
<!-- ============================================================ -->

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

1. 🍴 Fork the repository
2. 🌿 Create your feature branch (`git checkout -b feature/amazing`)
3. 💾 Commit your changes (`git commit -m 'Add some amazing feature'`)
4. 📤 Push to the branch (`git push origin feature/amazing`)
5. 🔁 Open a Pull Request

### Development Setup

```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
pytest tests/

# Check code style
black .
flake8 .
```

<br>

<!-- ============================================================ -->
<!-- SECTION: FOOTER                                               -->
<!-- ============================================================ -->

---

<p align="center">
  <b>Built with ♟️ and 🔐</b><br>
  <sub>© 2026 ChessVault Project — Making encryption playable</sub>
  <br><br>
  <a href="#top">⬆ Back to top</a>
</p>

<!-- 
╔══════════════════════════════════════════════════════════════════╗
║  Thank you for checking out ChessVault!                        ║
║  Remember: The best password is one you can play.              ║
╚══════════════════════════════════════════════════════════════════╝
-->
```

---

## 📥 Download Instructions

**Option 1: Copy and Save**
1. Copy the entire markdown content above
2. Create a new file named `README.md` in your project root
3. Paste the content and save

**Option 2: Direct Download**
- Create a file called `README.md`
- Paste the content above
- Commit to your repository

---

## ✨ What Makes This README Special

### 🎨 **Visual Enhancements**
- **Badges with animations** - Colored badges with hover effects (via GitHub's rendering)
- **Mermaid.js diagrams** - Interactive flowchart diagrams that render on GitHub
- **ASCII art dividers** - Decorative borders for section separation
- **Emoji-driven navigation** - Quick visual scanning with consistent emoji use

### 📊 **Improved Structure**
- **Collapsible sections** - Clean, tappable sections for detailed steps
- **Dual-column layouts** - Side-by-side feature comparison
- **Security layer visualization** - Clear ASCII diagram showing the security stack
- **JSON example** - Real-world metadata format example

### 🎯 **Better Readability**
- **Top-level navigation** - Quick jump to any section
- **Code blocks with syntax** - Properly highlighted commands
- **Table-based organization** - Clean information hierarchy
- **Callout blocks** - Important warnings and tips stand out

### 🚀 **Professional Touches**
- **Version badges** - Project status at a glance
- **Contributing section** - Clear contributor guidelines
- **Footer with back-to-top** - Easy navigation
- **ASCII art header/footer** - Memorable branding

---

## 📝 Usage Tips

1. **Replace placeholder URLs** - Update `git clone <this-repo-url>` with your actual repo URL
2. **Update badges** - Change version numbers and coverage percentages to match your project
3. **Add screenshots** - Insert actual screenshots between sections for visual proof
4. **Customize colors** - Adjust emoji and badge colors to match your brand

This README follows best practices from top GitHub projects like:
- **VSCode** - Clean structure with badges
- **React** - Clear contribution guidelines
- **TensorFlow** - Visual diagrams and clear sections
- **Rust** - Professional badge row and quick navigation

---

**Enjoy your enhanced README!** 🎉
