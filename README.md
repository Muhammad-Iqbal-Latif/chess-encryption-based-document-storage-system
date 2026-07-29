# ♜ ChessVault

**A desktop vault that turns a legal chess game into a document encryption key.**

ChessVault is a Python/Tkinter application where the "password" for a document isn't typed — it's *played*. To lock a file, you make a sequence of legal moves on a real chess board. Those moves are canonicalized, run through PBKDF2, and used to derive the key that encrypts your document. To unlock it, someone has to replay the exact same game.

---

## Table of contents

- [Why a chess board](#why-a-chess-board)
- [How encryption actually works](#how-encryption-actually-works)
- [Features](#features)
- [Tech stack](#tech-stack)
- [Project layout](#project-layout)
- [Getting started](#getting-started)
- [Using it](#using-it)
- [Default admin account](#default-admin-account)
- [Security design](#security-design)
- [Vault file format](#vault-file-format)
- [What never reaches git](#what-never-reaches-git)
- [Known limitations](#known-limitations)
- [Possible next steps](#possible-next-steps)

---

## Why a chess board

Most "fun" encryption gimmicks stop at the gimmick. This one is trying to make an honest point about key derivation: a secret doesn't have to be a string you type — it can be *any* reproducible sequence of decisions, as long as both sides can recreate it exactly.

A chess game is a good fit for that:

- Every move is checked against real chess rules (piece movement, blocked paths, turn order), so the move list can't be arbitrary noise — it has to be a game someone actually played.
- The move order matters and is easy to write down, but hard to guess, especially past a handful of moves.
- It forces a real conversation with the "why is this secure" question, which is exactly the kind of thing worth interrogating in a security project rather than taking for granted.

The rest of this document is upfront about where that idea holds up and where it doesn't — see [Known limitations](#known-limitations).

## How encryption actually works

**Locking a document (sender side):**

```
Play ≥ 8 legal moves on the board
        │
        ▼
Canonicalize moves → "0001:e2>e4\n0002:e7>e5\n..."  (deterministic bytes)
        │
        ▼
PBKDF2-HMAC-SHA256, 600,000 iterations, random 16-byte salt
        │
        ▼
Fernet key (AES-128-CBC + HMAC-SHA256, authenticated)
        │
        ▼
Encrypt the document  →  <owner>_<name>.chessvault   (stored in the vault)
        │
        └────────────────────────────────────────────► <name>_moves.txt
                                                          (the replay instructions —
                                                           shared out-of-band with
                                                           the recipient)
```

**Unlocking a document (recipient side):** open the `.chessvault` file, replay the moves from `moves.txt` on a fresh board in the same order. ChessVault checks the move count and a SHA-256 fingerprint of the sequence before it even attempts decryption — so a wrong move gives you a clear "these moves don't match this vault" instead of a cryptic failure. If they match, the same KDF run reproduces the same key, Fernet decrypts the payload, and a stored SHA-256 hash of the original plaintext is checked to confirm nothing was corrupted in transit.

The move sequence is the actual secret here. The `.chessvault` file alone decrypts nothing.

## Features

| Area | What it does |
|---|---|
| **Accounts** | Username/password registration with format validation, PBKDF2-HMAC-SHA256 password hashing (310,000 iterations, per-user salt), automatic upgrade of any legacy SHA-256 hash on next login |
| **Roles** | `user` and `admin` roles, selected at login and enforced separately from the password check |
| **Chess encryption engine** | Full legal-move validation for all six piece types (pawns, rooks, knights, bishops, queens, kings), including blocked-path detection — not just "any two squares" |
| **Vault dashboard** | Live stats (vault count, encrypted storage used, access level), searchable/filterable vault browser, per-vault metadata (owner, move count, timestamp) |
| **Sender workflow** | "Encrypt a document" → pick a file → play a game → get a `.chessvault` file plus its matching `moves.txt` |
| **Recipient workflow** | "Open a received vault" → pick a `.chessvault` file → replay the moves → preview or download the decrypted document |
| **Admin console** | Read-only audit log of logins, registrations, and logouts; ability to delete any stored vault; owner visibility on every vault card |
| **Integrity checking** | Every decrypt is checked against a stored SHA-256 hash of the original plaintext, independent of Fernet's own authentication |

## Tech stack

| Layer | Choice |
|---|---|
| UI | [`customtkinter`](https://github.com/TomSchimansky/CustomTkinter) on top of Tkinter |
| Cryptography | [`cryptography`](https://cryptography.io/) — `Fernet`, `PBKDF2HMAC` |
| Storage | SQLite (accounts), flat files (`.chessvault` containers, logs) |
| Language | Python 3.11+ |

## Project layout

```
Final_project/
├── main.py               # App shell: auth, dashboard, vault browser, admin console
├── chess_encryption.py   # Chess board UI, move validation, KDF + Fernet, vault format
├── ui_theme.py           # Color palette, fonts, reusable widgets
├── requirements.txt
├── assets/               # Icons and logo
└── spy_documents/        # Runtime data — created on first launch, not tracked in git
    ├── users.db
    ├── logs.txt
    └── *.chessvault
```

## Getting started

**Prerequisites:** Python 3.11 or newer.

```bash
# 1. Get the code
git clone <this-repo-url>
cd Final_project

# 2. (recommended) create a virtual environment
python3 -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate

# 3. Install dependencies
python3 -m pip install --user --no-cache-dir --timeout 300 -r requirements.txt

# 4. Run it
python3 main.py
```

On first launch, ChessVault creates `spy_documents/`, initializes the SQLite database, and seeds a default admin account (below).

## Using it

**To send a document:**
1. Log in, then choose **Encrypt a document** on the dashboard.
2. Pick any file that isn't already a `.chessvault`.
3. Play at least 8 legal moves on the board — any legal game works, it doesn't need to make chess sense.
4. ChessVault writes the `.chessvault` file into the vault *and* exports a `moves.txt` with the exact move order. Send both files to the recipient, but keep them separate from each other (email one, message the other, etc.) — anyone who has both can decrypt it.

**To receive one:**
1. Choose **Open a received vault** and select the `.chessvault` file.
2. Replay the moves from `moves.txt`, in order, from a fresh board.
3. On a match, preview the document in place or export a decrypted copy.

Each vault card also has **Export** (copy the raw `.chessvault` container elsewhere) and, for admins, **Delete**.

## Default admin account

A first run seeds one account automatically:

| Field | Value |
|---|---|
| Username | `admin` |
| Password | `admin123` |
| Role | `admin` |

This exists so the app is usable out of the box. Change the password (or delete and recreate the account) before using ChessVault with anything you actually care about — the seeded credentials are not a secret.

## Security design

| Parameter | Value | Purpose |
|---|---|---|
| Password hashing | PBKDF2-HMAC-SHA256, 310,000 iterations, 16-byte random salt | Protects stored account passwords |
| Vault key derivation | PBKDF2-HMAC-SHA256, 600,000 iterations, 16-byte random salt, input = canonicalized move bytes | Turns a chess game into a 256-bit key |
| Document encryption | Fernet → AES-128-CBC + HMAC-SHA256 | Authenticated encryption of the document bytes |
| Minimum move count | 8 legal moves | Floor on key-derivation input length |
| Sequence fingerprint | SHA-256 of canonical moves, truncated to 16 hex chars | Stored *unencrypted* in metadata purely to reject a wrong move sequence quickly — it is not the key and doesn't need to be secret |
| Plaintext integrity | SHA-256 of the original document, checked after every decrypt | Catches corruption or tampering beyond Fernet's own MAC |

## Vault file format

Each `.chessvault` file is a small custom container:

```
┌─────────────────────────────┬───────────────┬────────────────────┬──────────────────┐
│ "CHESSVAULT" + version byte │ header length │ JSON metadata       │ Fernet token     │
│         (11 bytes)          │ (4-byte uint) │ (UTF-8, size above) │ (rest of file)   │
└─────────────────────────────┴───────────────┴────────────────────┴──────────────────┘
```

The JSON metadata includes the original filename, owner, creation time, KDF parameters, salt, move count, sequence fingerprint, and the plaintext SHA-256 — everything needed to *attempt* a decrypt, nothing needed to *succeed* at one without the moves.

## What never reaches git

`.gitignore` deliberately excludes everything that would make a cloned copy of this repo sensitive or stateful:

| Excluded | Why |
|---|---|
| `spy_documents/`, `secure_storage/`, `documents/` contents | Runtime data — databases, logs, and real encrypted vaults |
| `*.db`, `logs.txt`, `*.chessvault` | User accounts, audit history, encrypted payloads |
| `*_moves.txt`, `*move_sequence*.txt`, `*chess_key*.txt`, `recovery_keys/` | These are decryption secrets in plain text — same sensitivity class as a private key |
| `.venv/`, `__pycache__/` | Local environment and build artifacts |

## Known limitations

- **The moves file is the real secret.** Anyone holding both the `.chessvault` file and its `moves.txt` can decrypt it. Treat `moves.txt` like a password, not like a convenience export — it should never travel over the same channel as the vault file.
- **PBKDF2 strengthens the key derivation, not the source entropy.** It makes brute-forcing a *given* move sequence expensive, but it can't manufacture entropy the player didn't put in. A short, "normal-looking" opening is weaker than a longer, deliberately unusual one.
- **Single-machine trust model.** Login gates the UI, not the files on disk — anyone with direct filesystem access to `spy_documents/` bypasses the account layer entirely and only needs the crypto secret (the moves) to get anywhere.
- **No key wrapping between users yet.** Sharing the moves file is still a manual, out-of-band step for every document.

## Possible next steps

- Wrap the derived key with the recipient's public key (RSA-OAEP or similar) so the move sequence never has to leave the sender's machine
- Optional vault expiry or one-time-use decryption
- Per-vault audit trails instead of one global log
