##main-file##

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import shutil
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from tkinter import filedialog, messagebox

import customtkinter as ctk
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from chess_encryption import chess_encryption, read_vault_metadata


APP_TITLE = "Citadel Document Vault"
VALID_ROLES = {"user", "admin"}
PBKDF2_ITERATIONS = 260_000
RSA_KEY_SIZE = 3072


@dataclass
class ListedDocument:
    display_name: str
    path: Path
    owner: str
    original_name: str
    created_utc: str
    recipients: list[str]
    key_management: str


class SpyDocumentSystem:
    """Main GUI application for encrypted document storage."""

    def __init__(self) -> None:
        self.base_dir = Path(__file__).resolve().parent
        self.storage_dir = self.base_dir / "spy_documents"
        self.storage_dir.mkdir(parents=True, exist_ok=True)

        self.db_file = self.storage_dir / "users.db"
        self.log_file = self.storage_dir / "logs.txt"

        self.conn = sqlite3.connect(self.db_file)
        self.conn.row_factory = sqlite3.Row
        self.cursor = self.conn.cursor()
        self.init_db()

        self.current_user: str | None = None
        self.current_role: str | None = None
        self.session_password: str | None = None
        self.visible_documents: list[ListedDocument] = []

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")

        self.root = ctk.CTk()
        self.root.title(APP_TITLE)
        self.root.geometry("1180x760")
        self.root.minsize(950, 620)
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        self.show_login_screen()

    # ------------------------------------------------------------------
    # Database, passwords, and user key pairs
    # ------------------------------------------------------------------
    def init_db(self) -> None:
        self.cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('user', 'admin')),
                created_utc TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                public_key TEXT,
                encrypted_private_key TEXT
            )
            """
        )
        self.conn.commit()

        self.cursor.execute("PRAGMA table_info(users)")
        existing_columns = {row[1] for row in self.cursor.fetchall()}
        migrations = {
            "created_utc": "ALTER TABLE users ADD COLUMN created_utc TEXT",
            "public_key": "ALTER TABLE users ADD COLUMN public_key TEXT",
            "encrypted_private_key": "ALTER TABLE users ADD COLUMN encrypted_private_key TEXT",
        }
        for column, query in migrations.items():
            if column not in existing_columns:
                self.cursor.execute(query)
        self.cursor.execute("UPDATE users SET created_utc=? WHERE created_utc IS NULL", (self.utc_now(),))
        self.conn.commit()

        self.cursor.execute("SELECT COUNT(*) AS total FROM users")
        if self.cursor.fetchone()["total"] == 0:
            public_key, encrypted_private_key = self.generate_user_keypair("admin123")
            self.cursor.execute(
                """
                INSERT INTO users
                (username, password, role, created_utc, public_key, encrypted_private_key)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    "admin",
                    self.hash_password("admin123"),
                    "admin",
                    self.utc_now(),
                    public_key,
                    encrypted_private_key,
                ),
            )
            self.conn.commit()
            self.log_event("Default admin account created with RSA key pair. Change the password after first use.")

    @staticmethod
    def utc_now() -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    @staticmethod
    def hash_password(password: str) -> str:
        salt = secrets.token_bytes(16)
        password_hash = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS
        )
        return "pbkdf2_sha256${}${}${}".format(
            PBKDF2_ITERATIONS,
            base64.urlsafe_b64encode(salt).decode("ascii"),
            base64.urlsafe_b64encode(password_hash).decode("ascii"),
        )

    @staticmethod
    def verify_password(password: str, stored_value: str) -> bool:
        if stored_value.startswith("pbkdf2_sha256$"):
            try:
                _name, iterations, salt_b64, hash_b64 = stored_value.split("$", 3)
                salt = base64.urlsafe_b64decode(salt_b64.encode("ascii"))
                expected_hash = base64.urlsafe_b64decode(hash_b64.encode("ascii"))
                actual_hash = hashlib.pbkdf2_hmac(
                    "sha256", password.encode("utf-8"), salt, int(iterations)
                )
                return hmac.compare_digest(actual_hash, expected_hash)
            except Exception:
                return False

        legacy_hash = hashlib.sha256(password.encode("utf-8")).hexdigest()
        return hmac.compare_digest(legacy_hash, stored_value)

    @staticmethod
    def generate_user_keypair(password: str) -> tuple[str, str]:
        """Generate an RSA key pair and encrypt the private key with the user's password."""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=RSA_KEY_SIZE)
        public_key_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        encrypted_private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password.encode("utf-8")),
        )
        return public_key_pem.decode("utf-8"), encrypted_private_key_pem.decode("utf-8")

    def ensure_user_keypair(self, username: str, password: str) -> None:
        """Create missing public/private keys for users migrated from the old version."""
        self.cursor.execute("SELECT public_key, encrypted_private_key FROM users WHERE username=?", (username,))
        row = self.cursor.fetchone()
        if not row:
            raise ValueError("User record not found.")
        if row["public_key"] and row["encrypted_private_key"]:
            return

        public_key, encrypted_private_key = self.generate_user_keypair(password)
        self.cursor.execute(
            "UPDATE users SET public_key=?, encrypted_private_key=? WHERE username=?",
            (public_key, encrypted_private_key, username),
        )
        self.conn.commit()
        self.log_event(f"RSA key pair generated for migrated user '{username}'.")

    def load_current_private_key(self):
        if not self.current_user or not self.session_password:
            raise ValueError("Session expired. Log in again.")
        self.cursor.execute("SELECT encrypted_private_key FROM users WHERE username=?", (self.current_user,))
        row = self.cursor.fetchone()
        if not row or not row["encrypted_private_key"]:
            raise ValueError("Private key is missing for the current user.")
        return serialization.load_pem_private_key(
            row["encrypted_private_key"].encode("utf-8"),
            password=self.session_password.encode("utf-8"),
        )

    def get_all_usernames(self) -> list[str]:
        # Only users with public keys can receive hybrid-encrypted documents.
        # Migrated users receive a key pair the next time they successfully log in.
        self.cursor.execute(
            """
            SELECT username FROM users
            WHERE public_key IS NOT NULL AND public_key != ''
            ORDER BY username COLLATE NOCASE
            """
        )
        names = [row["username"] for row in self.cursor.fetchall()]
        if self.current_user and self.current_user not in names:
            names.insert(0, self.current_user)
        return names or ([self.current_user] if self.current_user else [])

    def get_public_keys_for_users(self, usernames: list[str]) -> dict[str, str]:
        clean_names = sorted({name.strip() for name in usernames if name and name.strip()})
        if not clean_names:
            raise ValueError("No recipient selected.")
        placeholders = ",".join("?" for _ in clean_names)
        self.cursor.execute(
            f"SELECT username, public_key FROM users WHERE username IN ({placeholders})",
            clean_names,
        )
        result = {row["username"]: row["public_key"] for row in self.cursor.fetchall() if row["public_key"]}
        return result

    def validate_login(self, username: str, password: str, role: str) -> None:
        username = username.strip()
        role = role.strip().lower()

        if not username or not password:
            messagebox.showerror("Missing fields", "Enter both username and password.")
            return
        if role not in VALID_ROLES:
            messagebox.showerror("Invalid role", "Choose either User or Admin.")
            return

        self.cursor.execute("SELECT * FROM users WHERE username=? AND role=?", (username, role))
        user = self.cursor.fetchone()
        if not user or not self.verify_password(password, user["password"]):
            self.log_event(f"Failed login attempt for username='{username}' role='{role}'")
            messagebox.showerror("Login failed", "Invalid username, password, or role.")
            return

        if not user["password"].startswith("pbkdf2_sha256$"):
            self.cursor.execute(
                "UPDATE users SET password=? WHERE username=?",
                (self.hash_password(password), username),
            )
            self.conn.commit()

        self.ensure_user_keypair(username, password)
        self.current_user = username
        self.current_role = role
        self.session_password = password
        self.log_event(f"{username} logged in as {role}")
        self.show_user_interface()

    def register_user(self, username: str, password: str) -> None:
        username = username.strip()
        if not username or not password:
            messagebox.showerror("Missing fields", "Enter both username and password.")
            return
        if len(username) < 3:
            messagebox.showerror("Weak username", "Username must be at least 3 characters.")
            return
        if len(password) < 8:
            messagebox.showerror("Weak password", "Password must be at least 8 characters.")
            return
        if any(ch in username for ch in "/\\:;,*?\"<>|"):
            messagebox.showerror("Invalid username", "Username contains invalid characters.")
            return

        try:
            public_key, encrypted_private_key = self.generate_user_keypair(password)
            self.cursor.execute(
                """
                INSERT INTO users
                (username, password, role, created_utc, public_key, encrypted_private_key)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    username,
                    self.hash_password(password),
                    "user",
                    self.utc_now(),
                    public_key,
                    encrypted_private_key,
                ),
            )
            self.conn.commit()
            self.log_event(f"New user registered with RSA key pair: {username}")
            messagebox.showinfo("Registration complete", "User registered successfully. Log in now.")
        except sqlite3.IntegrityError:
            messagebox.showerror("Username exists", "Choose a different username.")
        except Exception as exc:
            messagebox.showerror("Registration failed", str(exc))

    # ------------------------------------------------------------------
    # Logging and UI helpers
    # ------------------------------------------------------------------
    def log_event(self, event: str) -> None:
        with self.log_file.open("a", encoding="utf-8") as log:
            log.write(f"{self.utc_now()} - {event}\n")

    def clear_root(self) -> None:
        for widget in self.root.winfo_children():
            widget.destroy()

    def make_card(self, parent, title: str):
        card = ctk.CTkFrame(parent, corner_radius=18)
        ctk.CTkLabel(card, text=title, font=ctk.CTkFont(size=19, weight="bold")).pack(
            anchor="w", padx=18, pady=(16, 8)
        )
        return card

    # ------------------------------------------------------------------
    # Login screen
    # ------------------------------------------------------------------
    def show_login_screen(self) -> None:
        self.current_user = None
        self.current_role = None
        self.session_password = None
        self.clear_root()

        outer = ctk.CTkFrame(self.root, fg_color="transparent")
        outer.pack(fill="both", expand=True, padx=30, pady=30)
        outer.grid_columnconfigure(0, weight=1)
        outer.grid_rowconfigure(0, weight=1)

        card = ctk.CTkFrame(outer, corner_radius=24)
        card.grid(row=0, column=0)

        ctk.CTkLabel(card, text="Citadel Document Vault", font=ctk.CTkFont(size=30, weight="bold")).pack(
            padx=50, pady=(35, 6)
        )
        ctk.CTkLabel(
            card,
            text="Chess-derived hybrid AES encryption with RSA recipient key wrapping",
            font=ctk.CTkFont(size=14),
            text_color="#a9b7c6",
        ).pack(padx=50, pady=(0, 24))

        username_entry = ctk.CTkEntry(card, placeholder_text="Username", width=330, height=42)
        username_entry.pack(pady=8)
        password_entry = ctk.CTkEntry(card, placeholder_text="Password", show="*", width=330, height=42)
        password_entry.pack(pady=8)

        role_var = ctk.StringVar(value="user")
        role_frame = ctk.CTkFrame(card, fg_color="transparent")
        role_frame.pack(pady=10)
        ctk.CTkRadioButton(role_frame, text="User", variable=role_var, value="user").pack(side="left", padx=14)
        ctk.CTkRadioButton(role_frame, text="Admin", variable=role_var, value="admin").pack(side="left", padx=14)

        button_frame = ctk.CTkFrame(card, fg_color="transparent")
        button_frame.pack(pady=(12, 30))
        ctk.CTkButton(
            button_frame,
            text="Login",
            width=150,
            height=40,
            command=lambda: self.validate_login(username_entry.get(), password_entry.get(), role_var.get()),
        ).pack(side="left", padx=8)
        ctk.CTkButton(
            button_frame,
            text="Register User",
            width=150,
            height=40,
            fg_color="#2f5d50",
            hover_color="#3b7a68",
            command=lambda: self.register_user(username_entry.get(), password_entry.get()),
        ).pack(side="left", padx=8)

        ctk.CTkLabel(
            card,
            text="Default admin: admin / admin123  |  Change it before real use.",
            font=ctk.CTkFont(size=12),
            text_color="#c7a252",
        ).pack(pady=(0, 25))

        username_entry.focus_set()
        self.root.bind(
            "<Return>",
            lambda _event: self.validate_login(username_entry.get(), password_entry.get(), role_var.get()),
        )

    # ------------------------------------------------------------------
    # Main document interface
    # ------------------------------------------------------------------
    def show_user_interface(self) -> None:
        if not self.current_user or not self.current_role:
            self.show_login_screen()
            return

        self.root.unbind("<Return>")
        self.clear_root()

        main = ctk.CTkFrame(self.root, corner_radius=0)
        main.pack(fill="both", expand=True)
        main.grid_columnconfigure(0, weight=1)
        main.grid_columnconfigure(1, weight=2)
        main.grid_rowconfigure(1, weight=1)

        header = ctk.CTkFrame(main, corner_radius=0, height=74)
        header.grid(row=0, column=0, columnspan=2, sticky="ew")
        header.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(header, text=f"Welcome, Agent {self.current_user}", font=ctk.CTkFont(size=24, weight="bold")).grid(
            row=0, column=0, sticky="w", padx=24, pady=18
        )
        ctk.CTkLabel(header, text=f"Role: {self.current_role.upper()}", text_color="#a9b7c6").grid(
            row=0, column=1, padx=10
        )
        ctk.CTkButton(header, text="Logout", width=100, command=self.show_login_screen).grid(row=0, column=2, padx=20)

        left_card = self.make_card(main, "Encrypt New Document")
        left_card.grid(row=1, column=0, sticky="nsew", padx=(24, 12), pady=24)

        ctk.CTkLabel(
            left_card,
            text=(
                "Choose a file, choose a recipient, create a chess move sequence, then encrypt it. "
                "The AES key is automatically wrapped with the recipient's RSA public key."
            ),
            wraplength=360,
            justify="left",
            text_color="#b8c2cc",
        ).pack(anchor="w", padx=18, pady=(0, 18))

        ctk.CTkButton(left_card, text="Select and Encrypt Document", height=42, command=self.select_document).pack(
            fill="x", padx=18, pady=(0, 12)
        )

        ctk.CTkLabel(
            left_card,
            text=(
                "Hybrid sharing is now enabled: the receiver does not need the chess sequence. "
                "They decrypt using their own account/private key."
            ),
            wraplength=360,
            justify="left",
            text_color="#d6b95f",
        ).pack(anchor="w", padx=18, pady=(8, 20))

        if self.current_role == "admin":
            admin_card = self.make_card(left_card, "Admin Tools")
            admin_card.pack(fill="x", padx=18, pady=(8, 18))
            ctk.CTkButton(admin_card, text="View Audit Logs", command=self.view_logs).pack(fill="x", padx=14, pady=(0, 14))

        right_card = self.make_card(main, "Stored Documents")
        right_card.grid(row=1, column=1, sticky="nsew", padx=(12, 24), pady=24)

        self.doc_listbox = ctk.CTkTextbox(right_card, height=420, activate_scrollbars=True)
        self.doc_listbox.pack(fill="both", expand=True, padx=18, pady=(0, 12))
        self.doc_listbox.configure(state="disabled")

        self.selected_index_var = ctk.StringVar(value="")
        select_frame = ctk.CTkFrame(right_card, fg_color="transparent")
        select_frame.pack(fill="x", padx=18, pady=(0, 8))
        select_frame.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(select_frame, text="Document #").grid(row=0, column=0, padx=(0, 8))
        ctk.CTkEntry(select_frame, textvariable=self.selected_index_var, width=90).grid(row=0, column=1, sticky="w")

        actions = ctk.CTkFrame(right_card, fg_color="transparent")
        actions.pack(fill="x", padx=18, pady=(0, 18))
        actions.grid_columnconfigure((0, 1, 2), weight=1)
        ctk.CTkButton(actions, text="Decrypt / View", command=self.view_document).grid(row=0, column=0, sticky="ew", padx=5)
        ctk.CTkButton(actions, text="Download Decrypted", command=self.download_document).grid(row=0, column=1, sticky="ew", padx=5)
        ctk.CTkButton(actions, text="Refresh", command=self.refresh_document_list).grid(row=0, column=2, sticky="ew", padx=5)

        if self.current_role == "admin":
            ctk.CTkButton(
                actions,
                text="Delete",
                fg_color="#7a2e2e",
                hover_color="#9a3939",
                command=self.delete_document,
            ).grid(row=1, column=0, columnspan=3, sticky="ew", padx=5, pady=(10, 0))

        self.refresh_document_list()

    def refresh_document_list(self) -> None:
        self.visible_documents = self.scan_documents()
        self.doc_listbox.configure(state="normal")
        self.doc_listbox.delete("1.0", "end")

        if not self.visible_documents:
            self.doc_listbox.insert("end", "No encrypted documents found for this account.\n")
        else:
            for index, doc in enumerate(self.visible_documents, start=1):
                recipients = ", ".join(doc.recipients) if doc.recipients else "legacy/unknown"
                self.doc_listbox.insert(
                    "end",
                    f"[{index}] {doc.original_name}\n"
                    f"    Sender/Owner: {doc.owner}\n"
                    f"    Recipients: {recipients}\n"
                    f"    Key management: {doc.key_management or 'legacy chess key'}\n"
                    f"    Created: {doc.created_utc or 'Unknown'}\n"
                    f"    Vault file: {doc.path.name}\n\n",
                )
        self.doc_listbox.configure(state="disabled")

    def scan_documents(self) -> list[ListedDocument]:
        documents: list[ListedDocument] = []
        for path in sorted(self.storage_dir.glob("*.chessvault"), key=lambda p: p.stat().st_mtime, reverse=True):
            metadata = read_vault_metadata(path) or {}
            owner = metadata.get("sender") or metadata.get("owner", "unknown")
            original_name = metadata.get("original_filename", path.stem)
            created_utc = metadata.get("created_utc", "")
            recipients = metadata.get("recipients", [])
            key_management = metadata.get("key_management", "LEGACY_CHESS_DERIVED_KEY")

            if self.current_role != "admin":
                allowed = owner == self.current_user or self.current_user in recipients
                if not allowed:
                    continue

            documents.append(
                ListedDocument(
                    display_name=original_name,
                    path=path,
                    owner=owner,
                    original_name=original_name,
                    created_utc=created_utc,
                    recipients=list(recipients),
                    key_management=key_management,
                )
            )
        return documents

    def get_selected_document(self) -> ListedDocument | None:
        raw = self.selected_index_var.get().strip()
        if not raw:
            messagebox.showwarning("No selection", "Enter the document number first.")
            return None
        try:
            index = int(raw)
        except ValueError:
            messagebox.showerror("Invalid selection", "Document number must be numeric.")
            return None
        if index < 1 or index > len(self.visible_documents):
            messagebox.showerror("Invalid selection", "No document exists with that number.")
            return None
        return self.visible_documents[index - 1]

    # ------------------------------------------------------------------
    # Document actions
    # ------------------------------------------------------------------
    def select_document(self) -> None:
        file_path = filedialog.askopenfilename(title="Select document to encrypt")
        if file_path:
            self.open_chess_window(Path(file_path), default_mode="encrypt")

    def view_document(self) -> None:
        doc = self.get_selected_document()
        if doc:
            self.open_chess_window(doc.path, default_mode="decrypt", preview_after_decrypt=True)

    def download_document(self) -> None:
        doc = self.get_selected_document()
        if doc:
            self.open_chess_window(doc.path, default_mode="decrypt", save_after_decrypt=True)

    def open_chess_window(
        self,
        file_path: Path,
        default_mode: str,
        preview_after_decrypt: bool = False,
        save_after_decrypt: bool = False,
    ) -> None:
        if not self.current_user:
            messagebox.showerror("Session expired", "Log in again.")
            self.show_login_screen()
            return

        window = ctk.CTkToplevel(self.root)
        window.title("Chess Hybrid AES Processor")
        window.geometry("1220x800")
        window.transient(self.root)
        window.grab_set()

        def on_complete(result_path: str | None, mode: str, metadata: dict | None = None) -> None:
            if not result_path:
                return
            result = Path(result_path)

            if mode == "encrypt":
                recipients = ", ".join((metadata or {}).get("recipients", []))
                self.log_event(f"{self.current_user} encrypted '{Path(file_path).name}' -> '{result.name}' for [{recipients}]")
                self.refresh_document_list()
                messagebox.showinfo(
                    "Encrypted",
                    "Document stored successfully.\n\n"
                    f"Vault: {result.name}\n"
                    f"Recipients: {recipients}",
                )
                return

            original_name = (metadata or {}).get("original_filename", result.name)
            self.log_event(f"{self.current_user} decrypted '{Path(file_path).name}'")

            if save_after_decrypt:
                save_path = filedialog.asksaveasfilename(title="Save decrypted document as", initialfile=original_name)
                if save_path:
                    shutil.copyfile(result, save_path)
                    messagebox.showinfo("Downloaded", f"Decrypted file saved to:\n{save_path}")
                return

            if preview_after_decrypt:
                self.show_decrypted_preview(result, original_name)

        chess_encryption(
            root=window,
            selected_file=str(file_path),
            app_output_directory=str(self.storage_dir),
            current_user=self.current_user,
            default_mode=default_mode,
            on_complete=on_complete,
            available_recipients=self.get_all_usernames(),
            public_key_resolver=self.get_public_keys_for_users,
            private_key_loader=self.load_current_private_key,
        )

    def show_decrypted_preview(self, file_path: Path, original_name: str) -> None:
        preview = ctk.CTkToplevel(self.root)
        preview.title(f"Preview - {original_name}")
        preview.geometry("900x650")
        preview.transient(self.root)

        ctk.CTkLabel(preview, text=f"Decrypted Preview: {original_name}", font=ctk.CTkFont(size=20, weight="bold")).pack(
            anchor="w", padx=18, pady=(18, 8)
        )
        text = ctk.CTkTextbox(preview, wrap="word")
        text.pack(fill="both", expand=True, padx=18, pady=(0, 18))

        try:
            data = file_path.read_bytes()
            text.insert("1.0", data.decode("utf-8"))
        except UnicodeDecodeError:
            text.insert(
                "1.0",
                "This file is not plain text, so it cannot be previewed safely here.\n"
                f"Temporary decrypted file path:\n{file_path}\n\n"
                "Use 'Download Decrypted' to save it properly.",
            )
        except Exception as exc:
            text.insert("1.0", f"Preview failed: {exc}")
        text.configure(state="disabled")

    def delete_document(self) -> None:
        doc = self.get_selected_document()
        if not doc:
            return
        if not messagebox.askyesno("Confirm delete", f"Delete this vault file?\n\n{doc.path.name}"):
            return
        try:
            doc.path.unlink()
            self.log_event(f"{self.current_user} deleted '{doc.path.name}'")
            self.refresh_document_list()
            messagebox.showinfo("Deleted", "Document deleted successfully.")
        except Exception as exc:
            messagebox.showerror("Delete failed", str(exc))

    def view_logs(self) -> None:
        if self.current_role != "admin":
            messagebox.showerror("Access denied", "Only admins can view logs.")
            return

        self.clear_root()
        frame = ctk.CTkFrame(self.root, corner_radius=18)
        frame.pack(fill="both", expand=True, padx=24, pady=24)
        ctk.CTkLabel(frame, text="Audit Logs", font=ctk.CTkFont(size=24, weight="bold")).pack(anchor="w", padx=18, pady=(18, 10))

        logs_text = ctk.CTkTextbox(frame, wrap="word")
        logs_text.pack(fill="both", expand=True, padx=18, pady=(0, 18))
        if self.log_file.exists():
            logs_text.insert("1.0", self.log_file.read_text(encoding="utf-8", errors="replace"))
        else:
            logs_text.insert("1.0", "No logs found.")
        logs_text.configure(state="disabled")

        ctk.CTkButton(frame, text="Back", command=self.show_user_interface).pack(pady=(0, 18))

    def on_close(self) -> None:
        try:
            self.conn.close()
        finally:
            self.root.destroy()

    def run(self) -> None:
        self.root.mainloop()


if __name__ == "__main__":
    SpyDocumentSystem().run()
