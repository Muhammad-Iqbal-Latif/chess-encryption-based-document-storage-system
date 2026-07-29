from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import shutil
import sqlite3
import tkinter as tk
from datetime import datetime, timezone
from pathlib import Path
from tkinter import filedialog

import customtkinter as ctk

from chess_encryption import (
    VAULT_EXTENSION,
    VaultFormatError,
    VaultResult,
    chess_encryption,
    read_vault,
)
from ui_theme import (
    COLORS,
    GradientCanvas,
    apply_window_icon,
    center_window,
    configure_customtkinter,
    danger_button,
    font,
    format_bytes,
    format_timestamp,
    logo_image,
    mono_font,
    primary_button,
    secondary_button,
    show_dialog,
)


USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
PASSWORD_ITERATIONS = 310_000


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS)
    return "pbkdf2_sha256${}${}${}".format(
        PASSWORD_ITERATIONS,
        base64.urlsafe_b64encode(salt).decode("ascii"),
        base64.urlsafe_b64encode(digest).decode("ascii"),
    )


def verify_password(password: str, stored_value: str) -> tuple[bool, bool]:
    """Return (password_matches, stored_hash_is_legacy_sha256)."""
    if stored_value.startswith("pbkdf2_sha256$"):
        try:
            _, iterations_text, salt_text, digest_text = stored_value.split("$", 3)
            iterations = int(iterations_text)
            salt = base64.urlsafe_b64decode(salt_text.encode("ascii"))
            expected = base64.urlsafe_b64decode(digest_text.encode("ascii"))
        except (ValueError, TypeError, base64.binascii.Error):
            return False, False
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
        return hmac.compare_digest(actual, expected), False

    # Backward compatibility for databases created by the original project.
    if re.fullmatch(r"[0-9a-fA-F]{64}", stored_value):
        actual = hashlib.sha256(password.encode("utf-8")).hexdigest()
        return hmac.compare_digest(actual.lower(), stored_value.lower()), True
    return False, False


class SpyDocumentSystem:
    def __init__(self) -> None:
        configure_customtkinter()

        self.base_directory = Path(__file__).resolve().parent
        self.storage_directory = self.base_directory / "spy_documents"
        self.storage_directory.mkdir(parents=True, exist_ok=True)
        self.database_path = self.storage_directory / "users.db"
        self.log_path = self.storage_directory / "logs.txt"

        self.root = ctk.CTk()
        self.root.title("ChessVault — Secure Document Exchange")
        self.root.configure(fg_color=COLORS["background"])
        self.root.minsize(1180, 740)
        self.root.protocol("WM_DELETE_WINDOW", self.close)
        center_window(self.root, 1480, 900)
        apply_window_icon(self.root)

        self.current_user: str | None = None
        self.current_role: str | None = None
        self.accessible_vaults: list[Path] = []
        self._background_canvas: GradientCanvas | None = None
        self._banner_after_id: str | None = None

        self.connection = sqlite3.connect(self.database_path)
        self.cursor = self.connection.cursor()
        self.init_database()
        self.show_login_screen()

    # ------------------------------------------------------------------
    # Database and authentication
    # ------------------------------------------------------------------
    def init_database(self) -> None:
        self.cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('user', 'admin'))
            )
            """
        )
        self.connection.commit()

        self.cursor.execute("SELECT COUNT(*) FROM users")
        if self.cursor.fetchone()[0] == 0:
            self.cursor.execute(
                "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                ("admin", hash_password("admin123"), "admin"),
            )
            self.connection.commit()

    def validate_login(self, username: str, password: str, role: str) -> None:
        username = username.strip()
        if not username or not password:
            show_dialog(
                self.root,
                "Credentials required",
                "Enter both your username and password before continuing.",
                kind="warning",
            )
            return

        self.cursor.execute("SELECT password, role FROM users WHERE username = ?", (username,))
        row = self.cursor.fetchone()
        if row is None:
            self._show_login_failure()
            return

        stored_password, stored_role = row
        password_matches, legacy_hash = verify_password(password, stored_password)
        if not password_matches or role != stored_role:
            self._show_login_failure()
            return

        if legacy_hash:
            self.cursor.execute(
                "UPDATE users SET password = ? WHERE username = ?",
                (hash_password(password), username),
            )
            self.connection.commit()

        self.current_user = username
        self.current_role = stored_role
        self.log_event(f"User '{username}' logged in as {stored_role}.")
        self.show_user_interface()

    def _show_login_failure(self) -> None:
        show_dialog(
            self.root,
            "Access denied",
            "The username, password, or selected access role is incorrect.",
            kind="error",
        )

    def register_user(self, username: str, password: str, confirmation: str, parent: tk.Misc | None = None) -> bool:
        dialog_parent = parent or self.root
        username = username.strip()
        if not USERNAME_PATTERN.fullmatch(username):
            show_dialog(
                dialog_parent,
                "Invalid username",
                "Use 3–32 characters containing only letters, numbers, dots, underscores, or hyphens.",
                kind="warning",
            )
            return False
        if len(password) < 8:
            show_dialog(
                dialog_parent,
                "Password too short",
                "Create a password containing at least eight characters.",
                kind="warning",
            )
            return False
        if password != confirmation:
            show_dialog(
                dialog_parent,
                "Passwords do not match",
                "Re-enter the same password in both password fields.",
                kind="warning",
            )
            return False

        try:
            self.cursor.execute(
                "INSERT INTO users (username, password, role) VALUES (?, ?, 'user')",
                (username, hash_password(password)),
            )
            self.connection.commit()
        except sqlite3.IntegrityError:
            show_dialog(
                dialog_parent,
                "Username unavailable",
                "That username already exists. Choose another username.",
                kind="error",
            )
            return False

        self.log_event(f"New user registered: '{username}'.")
        show_dialog(
            dialog_parent,
            "Account created",
            "Your ChessVault account is ready. Sign in using the new credentials.",
            kind="success",
        )
        return True

    def log_event(self, event: str) -> None:
        timestamp = datetime.now(timezone.utc).isoformat()
        with self.log_path.open("a", encoding="utf-8") as log:
            log.write(f"{timestamp} - {event}\n")

    # ------------------------------------------------------------------
    # Login and registration UI
    # ------------------------------------------------------------------
    def show_login_screen(self) -> None:
        self.current_user = None
        self.current_role = None
        self.clear_root()

        canvas = GradientCanvas(self.root, COLORS["void"], "#0C1727")
        canvas.pack(fill="both", expand=True)
        self._background_canvas = canvas

        shell = ctk.CTkFrame(
            canvas,
            width=1160,
            height=690,
            fg_color=COLORS["surface"],
            corner_radius=28,
            border_width=1,
            border_color=COLORS["border"],
        )
        shell.place(relx=0.5, rely=0.5, anchor="center")
        shell.pack_propagate(False)
        shell.grid_propagate(False)
        shell.grid_columnconfigure(0, weight=12, uniform="login")
        shell.grid_columnconfigure(1, weight=10, uniform="login")
        shell.grid_rowconfigure(0, weight=1)

        hero = ctk.CTkFrame(shell, fg_color="#0C1422", corner_radius=27)
        hero.grid(row=0, column=0, sticky="nsew", padx=(1, 0), pady=1)
        hero.grid_columnconfigure(0, weight=1)
        hero.grid_rowconfigure(5, weight=1)

        brand = ctk.CTkFrame(hero, fg_color="transparent")
        brand.grid(row=0, column=0, sticky="ew", padx=42, pady=(38, 0))
        brand_logo = logo_image(52)
        brand.logo_reference = brand_logo
        ctk.CTkLabel(brand, text="", image=brand_logo).pack(side="left")
        wordmark = ctk.CTkFrame(brand, fg_color="transparent")
        wordmark.pack(side="left", padx=(14, 0))
        ctk.CTkLabel(
            wordmark,
            text="CHESSVAULT",
            text_color=COLORS["text"],
            font=font(18, "bold"),
            anchor="w",
        ).pack(anchor="w")
        ctk.CTkLabel(
            wordmark,
            text="SECURE DOCUMENT EXCHANGE",
            text_color=COLORS["cyan"],
            font=mono_font(9, "bold"),
            anchor="w",
        ).pack(anchor="w", pady=(1, 0))

        ctk.CTkLabel(
            hero,
            text="Your moves.\nYour key.\nYour document.",
            text_color=COLORS["text"],
            font=font(44, "bold"),
            justify="left",
            anchor="w",
        ).grid(row=1, column=0, sticky="ew", padx=46, pady=(64, 14))

        ctk.CTkLabel(
            hero,
            text=(
                "A secure document vault where an exact chess sequence unlocks authenticated encryption — "
                "without private-key files or fragile key exchange steps."
            ),
            text_color=COLORS["text_secondary"],
            font=font(14),
            justify="left",
            anchor="w",
            wraplength=490,
        ).grid(row=2, column=0, sticky="ew", padx=47, pady=(0, 30))

        features = ctk.CTkFrame(hero, fg_color="transparent")
        features.grid(row=3, column=0, sticky="ew", padx=46)
        self._feature_row(features, "01", "Encrypted vault containers", "Versioned .chessvault storage with integrity verification")
        self._feature_row(features, "02", "Human-shareable move sequence", "An ordered TXT is generated automatically for the sender")
        self._feature_row(features, "03", "Controlled document recovery", "Recipients replay the sequence, then view or download")

        ctk.CTkLabel(
            hero,
            text="PBKDF2-HMAC-SHA256  •  FERNET  •  LOCAL-FIRST",
            text_color=COLORS["text_muted"],
            font=mono_font(9, "bold"),
            anchor="w",
        ).grid(row=6, column=0, sticky="sw", padx=47, pady=(0, 36))

        form_area = ctk.CTkFrame(shell, fg_color=COLORS["surface"], corner_radius=27)
        form_area.grid(row=0, column=1, sticky="nsew", padx=(0, 1), pady=1)
        form_area.grid_columnconfigure(0, weight=1)

        form = ctk.CTkFrame(form_area, fg_color="transparent")
        form.place(relx=0.5, rely=0.5, anchor="center", relwidth=0.76)

        ctk.CTkLabel(
            form,
            text="Secure sign in",
            text_color=COLORS["text"],
            font=font(29, "bold"),
            anchor="w",
        ).pack(fill="x")
        ctk.CTkLabel(
            form,
            text="Access your encrypted document workspace.",
            text_color=COLORS["text_secondary"],
            font=font(13),
            anchor="w",
        ).pack(fill="x", pady=(7, 30))

        ctk.CTkLabel(form, text="USERNAME", text_color=COLORS["text_muted"], font=mono_font(9, "bold"), anchor="w").pack(fill="x", pady=(0, 7))
        username_entry = self._entry(form, "Enter your username")
        username_entry.pack(fill="x")

        ctk.CTkLabel(form, text="PASSWORD", text_color=COLORS["text_muted"], font=mono_font(9, "bold"), anchor="w").pack(fill="x", pady=(20, 7))
        password_entry = self._entry(form, "Enter your password", show="•")
        password_entry.pack(fill="x")

        role_var = tk.StringVar(value="user")
        ctk.CTkLabel(form, text="ACCESS ROLE", text_color=COLORS["text_muted"], font=mono_font(9, "bold"), anchor="w").pack(fill="x", pady=(20, 8))
        role_switch = ctk.CTkFrame(
            form,
            fg_color=COLORS["background_2"],
            corner_radius=12,
            border_width=1,
            border_color=COLORS["border_soft"],
        )
        role_switch.pack(fill="x")
        role_switch.grid_columnconfigure((0, 1), weight=1)
        self._role_option(role_switch, "Standard user", "user", role_var, 0)
        self._role_option(role_switch, "Administrator", "admin", role_var, 1)

        login_button = primary_button(
            form,
            "Enter secure workspace",
            lambda: self.validate_login(username_entry.get(), password_entry.get(), role_var.get()),
        )
        login_button.pack(fill="x", pady=(28, 12))

        secondary_button(form, "Create a new user account", self.open_registration_dialog).pack(fill="x")

        ctk.CTkLabel(
            form,
            text="Your documents and credentials remain on this system.",
            text_color=COLORS["text_muted"],
            font=font(10),
        ).pack(pady=(24, 0))

        username_entry.focus_set()
        password_entry.bind(
            "<Return>",
            lambda _event: self.validate_login(username_entry.get(), password_entry.get(), role_var.get()),
        )

    def _feature_row(self, parent: tk.Misc, number: str, title: str, description: str) -> None:
        row = ctk.CTkFrame(parent, fg_color="transparent")
        row.pack(fill="x", pady=9)
        ctk.CTkLabel(
            row,
            text=number,
            width=42,
            height=42,
            corner_radius=12,
            fg_color=COLORS["cyan_dark"],
            text_color=COLORS["cyan"],
            font=mono_font(11, "bold"),
        ).pack(side="left")
        copy = ctk.CTkFrame(row, fg_color="transparent")
        copy.pack(side="left", fill="x", expand=True, padx=(13, 0))
        ctk.CTkLabel(copy, text=title, text_color=COLORS["text"], font=font(13, "bold"), anchor="w").pack(fill="x")
        ctk.CTkLabel(copy, text=description, text_color=COLORS["text_muted"], font=font(10), anchor="w").pack(fill="x", pady=(2, 0))

    def _entry(self, parent: tk.Misc, placeholder: str, **kwargs) -> ctk.CTkEntry:
        return ctk.CTkEntry(
            parent,
            placeholder_text=placeholder,
            height=48,
            corner_radius=12,
            fg_color=COLORS["background_2"],
            border_width=1,
            border_color=COLORS["border"],
            text_color=COLORS["text"],
            placeholder_text_color=COLORS["text_muted"],
            font=font(12),
            **kwargs,
        )

    def _role_option(self, parent: tk.Misc, label: str, value: str, variable: tk.StringVar, column: int) -> None:
        option = ctk.CTkRadioButton(
            parent,
            text=label,
            variable=variable,
            value=value,
            height=42,
            fg_color=COLORS["cyan"],
            hover_color=COLORS["cyan_hover"],
            border_color=COLORS["text_muted"],
            text_color=COLORS["text_secondary"],
            font=font(11, "bold"),
        )
        option.grid(row=0, column=column, padx=14, pady=7, sticky="w")

    def open_registration_dialog(self) -> None:
        dialog = ctk.CTkToplevel(self.root)
        dialog.title("Create ChessVault Account")
        dialog.configure(fg_color=COLORS["background"])
        dialog.resizable(False, False)
        dialog.transient(self.root)
        apply_window_icon(dialog)
        center_window(dialog, 540, 600, self.root)

        shell = ctk.CTkFrame(
            dialog,
            fg_color=COLORS["surface"],
            corner_radius=24,
            border_width=1,
            border_color=COLORS["border"],
        )
        shell.pack(fill="both", expand=True, padx=18, pady=18)

        ctk.CTkLabel(shell, text="Create account", text_color=COLORS["text"], font=font(25, "bold"), anchor="w").pack(fill="x", padx=30, pady=(30, 5))
        ctk.CTkLabel(
            shell,
            text="New registrations receive standard-user access.",
            text_color=COLORS["text_secondary"],
            font=font(12),
            anchor="w",
        ).pack(fill="x", padx=30, pady=(0, 26))

        fields = ctk.CTkFrame(shell, fg_color="transparent")
        fields.pack(fill="x", padx=30)

        ctk.CTkLabel(fields, text="USERNAME", text_color=COLORS["text_muted"], font=mono_font(9, "bold"), anchor="w").pack(fill="x", pady=(0, 7))
        username = self._entry(fields, "3–32 safe characters")
        username.pack(fill="x")

        ctk.CTkLabel(fields, text="PASSWORD", text_color=COLORS["text_muted"], font=mono_font(9, "bold"), anchor="w").pack(fill="x", pady=(19, 7))
        password = self._entry(fields, "At least eight characters", show="•")
        password.pack(fill="x")

        ctk.CTkLabel(fields, text="CONFIRM PASSWORD", text_color=COLORS["text_muted"], font=mono_font(9, "bold"), anchor="w").pack(fill="x", pady=(19, 7))
        confirmation = self._entry(fields, "Repeat your password", show="•")
        confirmation.pack(fill="x")

        def submit() -> None:
            if self.register_user(username.get(), password.get(), confirmation.get(), dialog):
                dialog.destroy()

        primary_button(fields, "Create secure account", submit).pack(fill="x", pady=(28, 11))
        secondary_button(fields, "Cancel", dialog.destroy).pack(fill="x")

        dialog.grab_set()
        username.focus_set()
        confirmation.bind("<Return>", lambda _event: submit())

    # ------------------------------------------------------------------
    # Dashboard UI
    # ------------------------------------------------------------------
    def show_user_interface(self) -> None:
        if self.current_user is None or self.current_role is None:
            self.show_login_screen()
            return

        self.clear_root()
        canvas = GradientCanvas(self.root, COLORS["void"], COLORS["background_2"])
        canvas.pack(fill="both", expand=True)
        self._background_canvas = canvas

        shell = ctk.CTkFrame(canvas, fg_color=COLORS["background"], corner_radius=24)
        shell.place(relx=0.5, rely=0.5, anchor="center", relwidth=0.965, relheight=0.95)
        shell.grid_columnconfigure(0, minsize=236)
        shell.grid_columnconfigure(1, weight=1)
        shell.grid_rowconfigure(0, weight=1)

        self._build_sidebar(shell)
        self.dashboard_content = ctk.CTkFrame(shell, fg_color=COLORS["background"], corner_radius=0)
        self.dashboard_content.grid(row=0, column=1, sticky="nsew")
        self.dashboard_content.grid_columnconfigure(0, weight=1)
        self.dashboard_content.grid_rowconfigure(4, weight=1)

        self._build_dashboard_header()
        self._build_banner()
        self._build_statistics()
        self._build_quick_actions()
        self._build_vault_browser()
        self.refresh_document_list()

    def _build_sidebar(self, parent: tk.Misc) -> None:
        sidebar = ctk.CTkFrame(parent, fg_color=COLORS["sidebar"], corner_radius=24)
        sidebar.grid(row=0, column=0, sticky="nsew", padx=(0, 1))
        sidebar.grid_rowconfigure(5, weight=1)

        brand = ctk.CTkFrame(sidebar, fg_color="transparent")
        brand.grid(row=0, column=0, sticky="ew", padx=24, pady=(26, 28))
        image = logo_image(44)
        brand.logo_reference = image
        ctk.CTkLabel(brand, text="", image=image).pack(side="left")
        copy = ctk.CTkFrame(brand, fg_color="transparent")
        copy.pack(side="left", padx=(11, 0))
        ctk.CTkLabel(copy, text="CHESSVAULT", text_color=COLORS["text"], font=font(14, "bold"), anchor="w").pack(anchor="w")
        ctk.CTkLabel(copy, text="CONTROL CENTER", text_color=COLORS["cyan"], font=mono_font(8, "bold"), anchor="w").pack(anchor="w")

        ctk.CTkLabel(sidebar, text="WORKSPACE", text_color=COLORS["text_muted"], font=mono_font(9, "bold"), anchor="w").grid(row=1, column=0, sticky="ew", padx=26, pady=(0, 9))
        self._sidebar_button(sidebar, "▦   Vault documents", self.show_user_interface, active=True).grid(row=2, column=0, sticky="ew", padx=14, pady=4)
        if self.current_role == "admin":
            self._sidebar_button(sidebar, "≡   Audit activity", self.view_logs).grid(row=3, column=0, sticky="ew", padx=14, pady=4)

        user_card = ctk.CTkFrame(
            sidebar,
            fg_color=COLORS["surface"],
            corner_radius=16,
            border_width=1,
            border_color=COLORS["border_soft"],
        )
        user_card.grid(row=6, column=0, sticky="ew", padx=16, pady=(8, 12))
        avatar_text = (self.current_user or "U")[:1].upper()
        ctk.CTkLabel(
            user_card,
            text=avatar_text,
            width=40,
            height=40,
            corner_radius=12,
            fg_color=COLORS["cyan_dark"],
            text_color=COLORS["cyan"],
            font=font(16, "bold"),
        ).pack(side="left", padx=12, pady=12)
        user_copy = ctk.CTkFrame(user_card, fg_color="transparent")
        user_copy.pack(side="left", fill="x", expand=True, pady=12)
        ctk.CTkLabel(user_copy, text=self.current_user or "User", text_color=COLORS["text"], font=font(11, "bold"), anchor="w").pack(fill="x")
        ctk.CTkLabel(user_copy, text=(self.current_role or "user").upper(), text_color=COLORS["text_muted"], font=mono_font(8, "bold"), anchor="w").pack(fill="x", pady=(2, 0))

        self._sidebar_button(sidebar, "↪   Sign out", self.logout).grid(row=7, column=0, sticky="ew", padx=14, pady=(0, 16))

    def _sidebar_button(self, parent: tk.Misc, text: str, command, active: bool = False) -> ctk.CTkButton:
        return ctk.CTkButton(
            parent,
            text=text,
            command=command,
            height=43,
            corner_radius=12,
            anchor="w",
            fg_color=COLORS["cyan_dark"] if active else "transparent",
            hover_color=COLORS["surface_hover"],
            text_color=COLORS["cyan"] if active else COLORS["text_secondary"],
            font=font(11, "bold"),
            border_width=1 if active else 0,
            border_color="#22565D",
        )

    def _build_dashboard_header(self) -> None:
        header = ctk.CTkFrame(self.dashboard_content, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=34, pady=(27, 12))
        header.grid_columnconfigure(0, weight=1)

        title = ctk.CTkFrame(header, fg_color="transparent")
        title.grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(
            title,
            text=f"Welcome back, {self.current_user}",
            text_color=COLORS["text"],
            font=font(27, "bold"),
            anchor="w",
        ).pack(anchor="w")
        ctk.CTkLabel(
            title,
            text="Encrypt, exchange, and recover documents through reproducible chess sequences.",
            text_color=COLORS["text_secondary"],
            font=font(12),
            anchor="w",
        ).pack(anchor="w", pady=(4, 0))

        status = ctk.CTkFrame(
            header,
            fg_color=COLORS["success_dark"],
            corner_radius=12,
            border_width=1,
            border_color="#245846",
        )
        status.grid(row=0, column=1, sticky="e")
        ctk.CTkLabel(status, text="●", text_color=COLORS["success"], font=font(12)).pack(side="left", padx=(13, 7), pady=9)
        ctk.CTkLabel(status, text="LOCAL VAULT ONLINE", text_color=COLORS["success"], font=mono_font(9, "bold")).pack(side="left", padx=(0, 13), pady=9)

    def _build_banner(self) -> None:
        self.banner_frame = ctk.CTkFrame(
            self.dashboard_content,
            fg_color=COLORS["success_dark"],
            corner_radius=12,
            border_width=1,
            border_color="#245846",
        )
        self.banner_label = ctk.CTkLabel(
            self.banner_frame,
            text="",
            text_color=COLORS["success"],
            font=font(11, "bold"),
            anchor="w",
            justify="left",
        )
        self.banner_label.pack(fill="x", padx=16, pady=11)

    def show_banner(self, message: str, kind: str = "success") -> None:
        if not hasattr(self, "banner_frame"):
            return
        palette = {
            "success": (COLORS["success_dark"], "#245846", COLORS["success"]),
            "warning": (COLORS["warning_dark"], "#65451F", COLORS["warning"]),
            "error": (COLORS["danger_dark"], "#6E2B39", COLORS["danger"]),
            "info": (COLORS["cyan_dark"], "#22565D", COLORS["cyan"]),
        }
        background, border, text = palette.get(kind, palette["success"])
        self.banner_frame.configure(fg_color=background, border_color=border)
        self.banner_label.configure(text=message, text_color=text)
        self.banner_frame.grid(row=1, column=0, sticky="ew", padx=34, pady=(0, 8))
        if self._banner_after_id:
            try:
                self.root.after_cancel(self._banner_after_id)
            except tk.TclError:
                pass
        self._banner_after_id = self.root.after(9000, self.banner_frame.grid_remove)

    def _build_statistics(self) -> None:
        stats = ctk.CTkFrame(self.dashboard_content, fg_color="transparent")
        stats.grid(row=2, column=0, sticky="ew", padx=34, pady=(4, 14))
        stats.grid_columnconfigure((0, 1, 2), weight=1, uniform="stats")

        self.vault_count_value = self._stat_card(stats, 0, "VAULTS", "0", "Encrypted containers", COLORS["cyan"])
        self.storage_value = self._stat_card(stats, 1, "STORAGE", "0 B", "Local encrypted payload", COLORS["blue"])
        self.role_value = self._stat_card(stats, 2, "ACCESS", (self.current_role or "user").upper(), "Current authorization level", COLORS["gold"])

    def _stat_card(self, parent: tk.Misc, column: int, label: str, value: str, caption: str, accent: str) -> ctk.CTkLabel:
        card = ctk.CTkFrame(
            parent,
            fg_color=COLORS["surface"],
            corner_radius=16,
            border_width=1,
            border_color=COLORS["border_soft"],
        )
        card.grid(row=0, column=column, sticky="ew", padx=(0 if column == 0 else 7, 0 if column == 2 else 7))
        accent_bar = ctk.CTkFrame(card, width=4, height=70, fg_color=accent, corner_radius=2)
        accent_bar.pack(side="left", padx=(14, 15), pady=16)
        accent_bar.pack_propagate(False)
        copy = ctk.CTkFrame(card, fg_color="transparent")
        copy.pack(side="left", fill="both", expand=True, pady=15)
        ctk.CTkLabel(copy, text=label, text_color=COLORS["text_muted"], font=mono_font(9, "bold"), anchor="w").pack(fill="x")
        value_label = ctk.CTkLabel(copy, text=value, text_color=COLORS["text"], font=font(22, "bold"), anchor="w")
        value_label.pack(fill="x", pady=(2, 0))
        ctk.CTkLabel(copy, text=caption, text_color=COLORS["text_muted"], font=font(9), anchor="w").pack(fill="x", pady=(2, 0))
        return value_label

    def _build_quick_actions(self) -> None:
        actions = ctk.CTkFrame(self.dashboard_content, fg_color="transparent")
        actions.grid(row=3, column=0, sticky="ew", padx=34, pady=(0, 14))
        actions.grid_columnconfigure((0, 1), weight=1, uniform="action")
        self._action_card(
            actions,
            0,
            "♜",
            "Encrypt a document",
            "Create a new .chessvault and automatically export its ordered move TXT.",
            "Begin sender workflow",
            self.select_document_for_encryption,
            COLORS["cyan"],
            COLORS["cyan_dark"],
        )
        self._action_card(
            actions,
            1,
            "⇩",
            "Open a received vault",
            "Select a .chessvault, inspect its requirements, and replay the sender's exact moves.",
            "Begin recipient workflow",
            self.open_received_vault,
            COLORS["gold"],
            COLORS["gold_dark"],
        )

    def _action_card(
        self,
        parent: tk.Misc,
        column: int,
        icon: str,
        title: str,
        description: str,
        button_text: str,
        command,
        accent: str,
        accent_dark: str,
    ) -> None:
        card = ctk.CTkFrame(
            parent,
            fg_color=COLORS["surface"],
            corner_radius=18,
            border_width=1,
            border_color=COLORS["border_soft"],
        )
        card.grid(row=0, column=column, sticky="nsew", padx=(0 if column == 0 else 7, 0 if column == 1 else 7))
        card.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(
            card,
            text=icon,
            width=58,
            height=58,
            corner_radius=17,
            fg_color=accent_dark,
            text_color=accent,
            font=font(27, "bold"),
        ).grid(row=0, column=0, rowspan=2, padx=(18, 15), pady=18, sticky="n")
        ctk.CTkLabel(card, text=title, text_color=COLORS["text"], font=font(15, "bold"), anchor="w").grid(row=0, column=1, sticky="ew", pady=(18, 3))
        ctk.CTkLabel(card, text=description, text_color=COLORS["text_muted"], font=font(10), anchor="w", justify="left", wraplength=360).grid(row=1, column=1, sticky="new", pady=(0, 16))
        ctk.CTkButton(
            card,
            text=button_text,
            command=command,
            height=36,
            width=170,
            corner_radius=10,
            fg_color=accent_dark,
            hover_color=accent,
            text_color=COLORS["text"],
            font=font(10, "bold"),
        ).grid(row=0, column=2, rowspan=2, padx=18, pady=18, sticky="e")

    def _build_vault_browser(self) -> None:
        vault_panel = ctk.CTkFrame(
            self.dashboard_content,
            fg_color=COLORS["surface"],
            corner_radius=18,
            border_width=1,
            border_color=COLORS["border_soft"],
        )
        vault_panel.grid(row=4, column=0, sticky="nsew", padx=34, pady=(0, 28))
        vault_panel.grid_rowconfigure(1, weight=1)
        vault_panel.grid_columnconfigure(0, weight=1)

        heading = ctk.CTkFrame(vault_panel, fg_color="transparent")
        heading.grid(row=0, column=0, sticky="ew", padx=20, pady=(17, 10))
        heading.grid_columnconfigure(0, weight=1)
        title = ctk.CTkFrame(heading, fg_color="transparent")
        title.grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(title, text="Encrypted vaults", text_color=COLORS["text"], font=font(16, "bold"), anchor="w").pack(anchor="w")
        ctk.CTkLabel(title, text="Local containers available to this account", text_color=COLORS["text_muted"], font=font(10), anchor="w").pack(anchor="w", pady=(2, 0))

        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *_args: self.render_vault_cards())
        search = ctk.CTkEntry(
            heading,
            textvariable=self.search_var,
            placeholder_text="Search vaults, owners, or original filenames",
            width=360,
            height=40,
            corner_radius=11,
            fg_color=COLORS["background_2"],
            border_width=1,
            border_color=COLORS["border"],
            text_color=COLORS["text"],
            placeholder_text_color=COLORS["text_muted"],
            font=font(10),
        )
        search.grid(row=0, column=1, sticky="e")

        self.vault_scroll = ctk.CTkScrollableFrame(
            vault_panel,
            fg_color="transparent",
            corner_radius=0,
            scrollbar_button_color=COLORS["surface_3"],
            scrollbar_button_hover_color=COLORS["cyan_dark"],
        )
        self.vault_scroll.grid(row=1, column=0, sticky="nsew", padx=13, pady=(0, 13))
        self.vault_scroll.grid_columnconfigure(0, weight=1)

    def refresh_document_list(self) -> None:
    
        try:
            self.accessible_vaults = sorted(
                self.storage_directory.glob(f"*{VAULT_EXTENSION}"),
                key=lambda path: path.stat().st_mtime,
                reverse=True,
            )
        except OSError:
            self.accessible_vaults = []

        total_size = 0
        for path in self.accessible_vaults:
            try:
                total_size += path.stat().st_size
            except OSError:
                continue

        if hasattr(self, "vault_count_value"):
            self.vault_count_value.configure(
                text=str(len(self.accessible_vaults))
            )

        if hasattr(self, "storage_value"):
            self.storage_value.configure(
                text=format_bytes(total_size)
            )

        if hasattr(self, "vault_scroll"):
            self.render_vault_cards()

    def render_vault_cards(self) -> None:
        if not hasattr(self, "vault_scroll"):
            return
        for widget in self.vault_scroll.winfo_children():
            widget.destroy()

        query = self.search_var.get().strip().lower() if hasattr(self, "search_var") else ""
        matches: list[tuple[Path, dict | None]] = []
        for path in self.accessible_vaults:
            metadata: dict | None
            try:
                metadata = read_vault(path).metadata
            except (OSError, VaultFormatError, ValueError):
                metadata = None
            searchable = " ".join(
                [
                    path.name,
                    str(metadata.get("original_filename", "")) if metadata else "",
                    str(metadata.get("owner", "")) if metadata else "",
                    str(metadata.get("sequence_id", "")) if metadata else "",
                ]
            ).lower()
            if not query or query in searchable:
                matches.append((path, metadata))

        if not matches:
            empty = ctk.CTkFrame(self.vault_scroll, fg_color="transparent")
            empty.grid(row=0, column=0, sticky="nsew", pady=38)
            ctk.CTkLabel(empty, text="♙", text_color=COLORS["text_muted"], font=font(38)).pack()
            ctk.CTkLabel(
                empty,
                text="No matching vaults",
                text_color=COLORS["text_secondary"],
                font=font(14, "bold"),
            ).pack(pady=(7, 3))
            ctk.CTkLabel(
                empty,
                text="Create a vault or change the current search.",
                text_color=COLORS["text_muted"],
                font=font(10),
            ).pack()
            return

        for row, (path, metadata) in enumerate(matches):
            self._vault_card(self.vault_scroll, row, path, metadata)

    def _vault_card(self, parent: tk.Misc, row: int, path: Path, metadata: dict | None) -> None:
        card = ctk.CTkFrame(
            parent,
            fg_color=COLORS["background_2"],
            corner_radius=14,
            border_width=1,
            border_color=COLORS["border_soft"],
        )
        card.grid(row=row, column=0, sticky="ew", padx=2, pady=5)
        card.grid_columnconfigure(1, weight=1)

        original_name = str(metadata.get("original_filename", path.stem)) if metadata else path.stem
        suffix = Path(original_name).suffix.lower().lstrip(".") or "vault"
        badge = suffix[:4].upper()
        ctk.CTkLabel(
            card,
            text=badge,
            width=58,
            height=58,
            corner_radius=14,
            fg_color=COLORS["blue_dark"],
            text_color=COLORS["blue"],
            font=mono_font(10, "bold"),
        ).grid(row=0, column=0, rowspan=2, padx=(14, 14), pady=14)

        display_name = path.name
        if self.current_role != "admin" and self.current_user and path.name.startswith(f"{self.current_user}_"):
            display_name = path.name[len(self.current_user) + 1 :]
        ctk.CTkLabel(card, text=display_name, text_color=COLORS["text"], font=font(12, "bold"), anchor="w").grid(row=0, column=1, sticky="sew", pady=(15, 1))

        owner = str(metadata.get("owner", "Unknown")) if metadata else "Unreadable metadata"
        move_count = str(metadata.get("move_count", "—")) if metadata else "—"
        details = f"Original: {original_name}   •   {format_bytes(path.stat().st_size)}   •   {move_count} moves   •   {format_timestamp(path.stat().st_mtime)}"
        if self.current_role == "admin":
            details += f"   •   Owner: {owner}"
        ctk.CTkLabel(card, text=details, text_color=COLORS["text_muted"], font=font(9), anchor="w").grid(row=1, column=1, sticky="new", pady=(1, 15))

        actions = ctk.CTkFrame(card, fg_color="transparent")
        actions.grid(row=0, column=2, rowspan=2, sticky="e", padx=14, pady=13)
        ctk.CTkButton(
            actions,
            text="Unlock",
            command=lambda p=path: self.show_chess_window(p, operation="decrypt"),
            width=92,
            height=35,
            corner_radius=10,
            fg_color=COLORS["cyan_dark"],
            hover_color=COLORS["cyan"],
            text_color=COLORS["cyan"],
            font=font(10, "bold"),
        ).pack(side="left", padx=4)
        ctk.CTkButton(
            actions,
            text="Export",
            command=lambda p=path: self.export_vault(p),
            width=82,
            height=35,
            corner_radius=10,
            fg_color=COLORS["surface_2"],
            hover_color=COLORS["surface_hover"],
            border_width=1,
            border_color=COLORS["border"],
            text_color=COLORS["text_secondary"],
            font=font(10, "bold"),
        ).pack(side="left", padx=4)
        if self.current_role == "admin":
            ctk.CTkButton(
                actions,
                text="Delete",
                command=lambda p=path: self.delete_document(p),
                width=75,
                height=35,
                corner_radius=10,
                fg_color=COLORS["danger_dark"],
                hover_color=COLORS["danger"],
                text_color=COLORS["danger"],
                font=font(10, "bold"),
            ).pack(side="left", padx=4)

    # ------------------------------------------------------------------
    # Vault operations
    # ------------------------------------------------------------------
    def select_document_for_encryption(self) -> None:
        path = filedialog.askopenfilename(
            parent=self.root,
            title="Select Document to Encrypt",
            filetypes=[("All supported documents", "*.*")],
        )
        if not path:
            return
        if path.lower().endswith(VAULT_EXTENSION):
            show_dialog(
                self.root,
                "Already encrypted",
                "Use the recipient workflow to unlock an existing .chessvault file.",
                kind="warning",
            )
            return
        self.show_chess_window(Path(path), operation="encrypt")

    def open_received_vault(self) -> None:
        path = filedialog.askopenfilename(
            parent=self.root,
            title="Open Received ChessVault",
            filetypes=[("ChessVault files", f"*{VAULT_EXTENSION}"), ("All files", "*.*")],
        )
        if path:
            self.show_chess_window(Path(path), operation="decrypt")

    def show_chess_window(self, file_path: Path, operation: str) -> None:
        window: ctk.CTkToplevel | None = None
        try:
            window = ctk.CTkToplevel(self.root)
            window.configure(fg_color=COLORS["background"])
            window.transient(self.root)
            chess_encryption(
                root=window,
                selected_file=file_path,
                app_output_directory=self.storage_directory,
                current_user=self.current_user or "recipient",
                operation=operation,
                on_encrypted=self.on_encryption_complete if operation == "encrypt" else None,
            )
            window.focus_force()
        except Exception as exc:
            if window is not None:
                try:
                    window.destroy()
                except tk.TclError:
                    pass
            show_dialog(self.root, "ChessVault error", str(exc), kind="error")

    def on_encryption_complete(self, result: VaultResult) -> None:
        self.log_event(
            f"User '{self.current_user}' encrypted '{result.original_filename}' as "
            f"'{result.vault_path.name}' with {result.move_count} moves."
        )
        self.refresh_document_list()
        self.show_banner(
            f"Vault created: {result.vault_path.name}   •   Move instructions: {result.moves_path}",
            kind="success",
        )

    def export_vault(self, source: Path) -> None:
        destination = filedialog.asksaveasfilename(
            parent=self.root,
            title="Export ChessVault File",
            initialfile=source.name,
            defaultextension=VAULT_EXTENSION,
            filetypes=[("ChessVault files", f"*{VAULT_EXTENSION}")],
        )
        if not destination:
            return
        try:
            shutil.copy2(source, destination)
        except OSError as exc:
            show_dialog(self.root, "Export failed", str(exc), kind="error")
            return
        self.log_event(f"User '{self.current_user}' exported vault '{source.name}'.")
        show_dialog(
            self.root,
            "Vault exported",
            "The encrypted container was copied successfully.",
            kind="success",
            details=destination,
        )

    def delete_document(self, path: Path) -> None:
        confirmed = show_dialog(
            self.root,
            "Delete encrypted vault?",
            "This permanently removes the selected .chessvault file from local storage.",
            kind="warning",
            details=path.name,
            confirm=True,
            confirm_text="Delete vault",
        )
        if not confirmed:
            return
        try:
            path.unlink()
        except OSError as exc:
            show_dialog(self.root, "Delete failed", str(exc), kind="error")
            return
        self.log_event(f"Administrator '{self.current_user}' deleted vault '{path.name}'.")
        self.refresh_document_list()
        self.show_banner(f"Deleted vault: {path.name}", kind="warning")

    # ------------------------------------------------------------------
    # Audit log UI
    # ------------------------------------------------------------------
    def view_logs(self) -> None:
        if self.current_role != "admin":
            return
        self.clear_root()
        canvas = GradientCanvas(self.root, COLORS["void"], COLORS["background_2"])
        canvas.pack(fill="both", expand=True)
        self._background_canvas = canvas

        shell = ctk.CTkFrame(
            canvas,
            fg_color=COLORS["surface"],
            corner_radius=24,
            border_width=1,
            border_color=COLORS["border"],
        )
        shell.place(relx=0.5, rely=0.5, anchor="center", relwidth=0.92, relheight=0.88)
        shell.grid_columnconfigure(0, weight=1)
        shell.grid_rowconfigure(1, weight=1)

        header = ctk.CTkFrame(shell, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=28, pady=(24, 14))
        ctk.CTkLabel(header, text="Audit activity", text_color=COLORS["text"], font=font(25, "bold"), anchor="w").pack(side="left")
        secondary_button(header, "Return to vaults", self.show_user_interface, width=150).pack(side="right")

        logs = ctk.CTkTextbox(
            shell,
            wrap="word",
            fg_color=COLORS["background_2"],
            border_width=1,
            border_color=COLORS["border_soft"],
            corner_radius=16,
            text_color=COLORS["text_secondary"],
            font=mono_font(11),
        )
        logs.grid(row=1, column=0, sticky="nsew", padx=28, pady=(0, 28))
        if self.log_path.exists():
            logs.insert("1.0", self.log_path.read_text(encoding="utf-8", errors="replace"))
        else:
            logs.insert("1.0", "No audit events have been recorded.")
        logs.configure(state="disabled")

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    def logout(self) -> None:
        if self.current_user:
            self.log_event(f"User '{self.current_user}' logged out.")
        self.show_login_screen()

    def clear_root(self) -> None:
        if self._banner_after_id:
            try:
                self.root.after_cancel(self._banner_after_id)
            except tk.TclError:
                pass
            self._banner_after_id = None
        for widget in self.root.winfo_children():
            widget.destroy()

    def close(self) -> None:
        try:
            self.connection.commit()
            self.connection.close()
        finally:
            self.root.destroy()

    def run(self) -> None:
        self.root.mainloop()


if __name__ == "__main__":
    SpyDocumentSystem().run()
