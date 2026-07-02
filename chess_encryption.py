###chess-encryption-file###

from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Any

import customtkinter as ctk
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


MAGIC_V2 = b"CHESSVAULT2\n"
MAGIC_V1 = b"CHESSVAULT1\n"
VERSION = 2
KDF_ITERATIONS = 390_000
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32


@dataclass
class ChessPiece:
    piece_type: str
    is_white: bool

    @property
    def color_letter(self) -> str:
        return "W" if self.is_white else "B"

    def symbol(self) -> str:
        symbols = {
            ("P", True): "♙", ("R", True): "♖", ("N", True): "♘", ("B", True): "♗", ("Q", True): "♕", ("K", True): "♔",
            ("P", False): "♟", ("R", False): "♜", ("N", False): "♞", ("B", False): "♝", ("Q", False): "♛", ("K", False): "♚",
        }
        return symbols.get((self.piece_type, self.is_white), " ")


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii")


def b64d(data: str) -> bytes:
    return base64.urlsafe_b64decode(data.encode("ascii"))


def sanitize_filename(name: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("._")
    return safe or "document"


def canonical_json(data: dict) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def derive_chess_component(chess_secret: str, salt: bytes, iterations: int = KDF_ITERATIONS) -> bytes:
    """Derive a fixed-length secret component from the chess move string.

    This is not used as the only key in the hybrid version. It is mixed with
    strong random bytes, then the final AES key is wrapped with RSA for sharing.
    """
    if not chess_secret or len(chess_secret.strip()) < 8:
        raise ValueError("Chess key material is too short. Make more moves or enter a longer chess phrase.")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(chess_secret.encode("utf-8"))


def derive_legacy_key(chess_secret: str, salt: bytes, iterations: int = KDF_ITERATIONS) -> bytes:
    return derive_chess_component(chess_secret, salt, iterations)


def make_hybrid_content_key(chess_component: bytes, random_seed: bytes, salt: bytes) -> bytes:
    """Create the AES key from chess entropy and cryptographic randomness."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        info=b"Citadel ChessVault hybrid AES-256 key v2",
    )
    return hkdf.derive(chess_component + random_seed)


def build_vault_blob(metadata: dict, ciphertext: bytes) -> bytes:
    header = canonical_json(metadata)
    return MAGIC_V2 + len(header).to_bytes(4, "big") + header + ciphertext


def parse_vault_blob(blob: bytes) -> tuple[dict, bytes, bytes]:
    if blob.startswith(MAGIC_V2):
        magic = MAGIC_V2
    elif blob.startswith(MAGIC_V1):
        magic = MAGIC_V1
    else:
        raise ValueError("This is not a supported .chessvault file.")

    start = len(magic)
    if len(blob) < start + 4:
        raise ValueError("Vault file is corrupted or incomplete.")

    header_size = int.from_bytes(blob[start : start + 4], "big")
    header_start = start + 4
    header_end = header_start + header_size

    if header_size <= 0 or header_end > len(blob):
        raise ValueError("Vault metadata is corrupted.")

    metadata = json.loads(blob[header_start:header_end].decode("utf-8"))
    ciphertext = blob[header_end:]
    return metadata, ciphertext, magic


def read_vault_metadata(path: str | Path) -> dict | None:
    try:
        metadata, _ciphertext, _magic = parse_vault_blob(Path(path).read_bytes())
        return metadata
    except Exception:
        return None


def v2_aad(metadata: dict) -> bytes:
    fields = {
        "version": metadata.get("version"),
        "algorithm": metadata.get("algorithm"),
        "key_management": metadata.get("key_management"),
        "sender": metadata.get("sender"),
        "owner": metadata.get("owner"),
        "original_filename": metadata.get("original_filename"),
        "created_utc": metadata.get("created_utc"),
        "recipients": metadata.get("recipients", []),
        "chess_fingerprint": metadata.get("chess_fingerprint"),
    }
    return canonical_json(fields)


def legacy_v1_aad(metadata: dict) -> bytes:
    fields = {
        k: metadata[k]
        for k in ("version", "algorithm", "owner", "original_filename")
        if k in metadata
    }
    return json.dumps(fields, separators=(",", ":")).encode("utf-8")


class chess_encryption:
    """GUI window for chess-derived hybrid AES encryption/decryption.

    The lowercase class name is kept for compatibility with the original project.
    """

    def __init__(
        self,
        root,
        selected_file: str,
        app_output_directory: str,
        current_user: str,
        default_mode: str = "encrypt",
        on_complete: Callable[[str | None, str, dict | None], None] | None = None,
        available_recipients: list[str] | None = None,
        public_key_resolver: Callable[[list[str]], dict[str, str]] | None = None,
        private_key_loader: Callable[[], Any] | None = None,
    ) -> None:
        self.root = root
        self.selected_file = Path(selected_file)
        self.output_directory = Path(app_output_directory)
        self.current_user = current_user
        self.default_mode = default_mode if default_mode in {"encrypt", "decrypt"} else "encrypt"
        self.on_complete = on_complete
        self.available_recipients = sorted(set(available_recipients or [current_user]))
        if current_user not in self.available_recipients:
            self.available_recipients.insert(0, current_user)
        self.public_key_resolver = public_key_resolver
        self.private_key_loader = private_key_loader

        self.output_directory.mkdir(parents=True, exist_ok=True)
        self.temp_dir = self.output_directory / ".decrypted_temp"
        self.temp_dir.mkdir(parents=True, exist_ok=True)

        # Detect vault type early so the UI can avoid asking for chess moves
        # when the file is a hybrid RSA-wrapped vault.
        self.selected_metadata = read_vault_metadata(self.selected_file) if self.selected_file.suffix == ".chessvault" else None
        self.is_hybrid_v2_vault = bool(
            self.selected_metadata
            and self.selected_metadata.get("key_management") == "HYBRID_RSA_OAEP_SHA256"
        )

        self.selected_square: tuple[int, int] | None = None
        self.moves_sequence: list[str] = []
        self.current_turn_is_white = True

        self.root.title("Chess Hybrid AES Processor")
        self.root.minsize(1080, 720)

        self.setup_board()
        self.setup_gui()
        self.update_board_display()

    # ------------------------------------------------------------------
    # Board setup and movement
    # ------------------------------------------------------------------
    def setup_board(self) -> None:
        self.board: list[list[ChessPiece | None]] = [[None for _ in range(8)] for _ in range(8)]
        back_rank = ["R", "N", "B", "Q", "K", "B", "N", "R"]

        for col, piece_type in enumerate(back_rank):
            self.board[0][col] = ChessPiece(piece_type, False)
            self.board[1][col] = ChessPiece("P", False)
            self.board[6][col] = ChessPiece("P", True)
            self.board[7][col] = ChessPiece(piece_type, True)

    @staticmethod
    def square_name(row: int, col: int) -> str:
        return f"{chr(97 + col)}{8 - row}"

    @staticmethod
    def square_color(row: int, col: int) -> str:
        return "#f0d9b5" if (row + col) % 2 == 0 else "#b58863"

    def piece_at(self, row: int, col: int) -> ChessPiece | None:
        return self.board[row][col]

    def is_path_clear(self, from_row: int, from_col: int, to_row: int, to_col: int) -> bool:
        row_step = 0 if from_row == to_row else (1 if to_row > from_row else -1)
        col_step = 0 if from_col == to_col else (1 if to_col > from_col else -1)
        row = from_row + row_step
        col = from_col + col_step
        while (row, col) != (to_row, to_col):
            if self.board[row][col] is not None:
                return False
            row += row_step
            col += col_step
        return True

    def is_valid_move(self, from_row: int, from_col: int, to_row: int, to_col: int) -> bool:
        if (from_row, from_col) == (to_row, to_col):
            return False

        piece = self.piece_at(from_row, from_col)
        if piece is None or piece.is_white != self.current_turn_is_white:
            return False

        target = self.piece_at(to_row, to_col)
        if target and target.is_white == piece.is_white:
            return False

        row_diff = to_row - from_row
        col_diff = to_col - from_col
        abs_row = abs(row_diff)
        abs_col = abs(col_diff)

        if piece.piece_type == "P":
            direction = -1 if piece.is_white else 1
            start_row = 6 if piece.is_white else 1
            if col_diff == 0 and target is None:
                if row_diff == direction:
                    return True
                if from_row == start_row and row_diff == 2 * direction:
                    return self.board[from_row + direction][from_col] is None
            if abs_col == 1 and row_diff == direction and target is not None:
                return target.is_white != piece.is_white
            return False

        if piece.piece_type == "R":
            return (row_diff == 0 or col_diff == 0) and self.is_path_clear(from_row, from_col, to_row, to_col)
        if piece.piece_type == "N":
            return (abs_row, abs_col) in {(1, 2), (2, 1)}
        if piece.piece_type == "B":
            return abs_row == abs_col and self.is_path_clear(from_row, from_col, to_row, to_col)
        if piece.piece_type == "Q":
            return (row_diff == 0 or col_diff == 0 or abs_row == abs_col) and self.is_path_clear(from_row, from_col, to_row, to_col)
        if piece.piece_type == "K":
            return abs_row <= 1 and abs_col <= 1
        return False

    def make_move_token(self, piece: ChessPiece, from_row: int, from_col: int, to_row: int, to_col: int) -> str:
        return f"{piece.color_letter}{piece.piece_type}:{self.square_name(from_row, from_col)}-{self.square_name(to_row, to_col)}"

    def on_square_click(self, row: int, col: int) -> None:
        if self.selected_square is None:
            piece = self.piece_at(row, col)
            if piece is None:
                self.set_status("Choose a piece first.")
                return
            if piece.is_white != self.current_turn_is_white:
                self.set_status("It is White's turn." if self.current_turn_is_white else "It is Black's turn.")
                return
            self.selected_square = (row, col)
            self.update_board_display()
            self.set_status(f"Selected {piece.symbol()} at {self.square_name(row, col)}")
            return

        from_row, from_col = self.selected_square
        piece = self.piece_at(from_row, from_col)
        if piece and self.is_valid_move(from_row, from_col, row, col):
            token = self.make_move_token(piece, from_row, from_col, row, col)
            self.moves_sequence.append(token)
            self.board[row][col] = piece
            self.board[from_row][from_col] = None
            self.current_turn_is_white = not self.current_turn_is_white
            self.moves_text.configure(state="normal")
            self.moves_text.insert("end", token + " ")
            self.moves_text.configure(state="disabled")
            self.set_status(f"Move added: {token}")
        else:
            self.set_status("Invalid move for the selected piece.")

        self.selected_square = None
        self.update_board_display()

    # ------------------------------------------------------------------
    # GUI
    # ------------------------------------------------------------------
    def setup_gui(self) -> None:
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_columnconfigure(1, weight=1)
        self.root.grid_rowconfigure(0, weight=1)

        self.left_panel = ctk.CTkFrame(self.root, corner_radius=18)
        self.right_panel = ctk.CTkFrame(self.root, corner_radius=18)
        self.left_panel.grid(row=0, column=0, sticky="nsew", padx=(18, 9), pady=18)
        self.right_panel.grid(row=0, column=1, sticky="nsew", padx=(9, 18), pady=18)

        self.setup_chess_board(self.left_panel)
        self.setup_control_panel(self.right_panel)

    def setup_chess_board(self, parent) -> None:
        parent.grid_columnconfigure(0, weight=1)
        self.chess_title_label = ctk.CTkLabel(parent, text="Chess Key Builder", font=ctk.CTkFont(size=22, weight="bold"))
        self.chess_title_label.grid(row=0, column=0, pady=(18, 6))

        board_frame = ctk.CTkFrame(parent, fg_color="transparent")
        board_frame.grid(row=1, column=0, pady=8)

        self.squares: list[list[ctk.CTkButton]] = []
        for row in range(8):
            square_row = []
            for col in range(8):
                square = ctk.CTkButton(
                    board_frame,
                    text="",
                    width=58,
                    height=58,
                    corner_radius=0,
                    font=ctk.CTkFont(size=28),
                    command=lambda r=row, c=col: self.on_square_click(r, c),
                )
                square.grid(row=row, column=col, padx=1, pady=1)
                square_row.append(square)
            self.squares.append(square_row)

        self.chess_hint_label = ctk.CTkLabel(
            parent,
            text="Files: a-h  |  Ranks: 1-8  |  White moves first",
            text_color="#b8c2cc",
        )
        self.chess_hint_label.grid(row=2, column=0, pady=(4, 10))

        self.reset_button = ctk.CTkButton(parent, text="Reset Board", command=self.reset_board, width=180)
        self.reset_button.grid(row=3, column=0, pady=(0, 18))

    def setup_control_panel(self, parent) -> None:
        parent.grid_columnconfigure(0, weight=1)
        parent.grid_rowconfigure(9, weight=1)

        ctk.CTkLabel(parent, text="Hybrid AES Processor", font=ctk.CTkFont(size=22, weight="bold")).grid(
            row=0, column=0, sticky="w", padx=18, pady=(18, 6)
        )

        ctk.CTkLabel(
            parent,
            text=f"Selected file: {self.selected_file.name}",
            text_color="#b8c2cc",
            wraplength=480,
            justify="left",
        ).grid(row=1, column=0, sticky="w", padx=18, pady=(0, 10))

        self.mode_var = ctk.StringVar(value=self.default_mode)
        mode_frame = ctk.CTkFrame(parent, fg_color="transparent")
        mode_frame.grid(row=2, column=0, sticky="w", padx=18, pady=4)
        ctk.CTkRadioButton(mode_frame, text="Encrypt", variable=self.mode_var, value="encrypt").pack(side="left", padx=(0, 16))
        ctk.CTkRadioButton(mode_frame, text="Decrypt", variable=self.mode_var, value="decrypt").pack(side="left")

        self.recipient_var = ctk.StringVar(value=self.current_user)
        recipient_frame = ctk.CTkFrame(parent, fg_color="transparent")
        recipient_frame.grid(row=3, column=0, sticky="ew", padx=18, pady=(8, 4))
        recipient_frame.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(recipient_frame, text="Recipient:").grid(row=0, column=0, padx=(0, 10), sticky="w")
        self.recipient_menu = ctk.CTkOptionMenu(
            recipient_frame,
            values=self.available_recipients,
            variable=self.recipient_var,
            width=220,
        )
        self.recipient_menu.grid(row=0, column=1, sticky="w")

        self.mode_explainer_label = ctk.CTkLabel(
            parent,
            text=(
                "Encryption: chess moves help generate a fresh AES key, then that AES key is encrypted "
                "with the recipient's RSA public key. Decryption does not require sharing the chess sequence."
            ),
            wraplength=500,
            justify="left",
            text_color="#d6b95f",
        )
        self.mode_explainer_label.grid(row=4, column=0, sticky="w", padx=18, pady=(8, 4))

        self.manual_key_label = ctk.CTkLabel(parent, text="Optional chess phrase:", anchor="w")
        self.manual_key_label.grid(row=5, column=0, sticky="w", padx=18, pady=(8, 0))

        self.manual_key_entry = ctk.CTkEntry(
            parent,
            placeholder_text="Optional chess phrase, for example: WN:g1-f3 BP:e7-e5 ...",
            height=40,
        )
        self.manual_key_entry.grid(row=6, column=0, sticky="ew", padx=18, pady=(6, 10))

        self.moves_label = ctk.CTkLabel(parent, text="Board move sequence:", anchor="w")
        self.moves_label.grid(row=7, column=0, sticky="w", padx=18, pady=(4, 0))
        self.moves_text = ctk.CTkTextbox(parent, height=92, wrap="word")
        self.moves_text.grid(row=8, column=0, sticky="ew", padx=18, pady=(4, 12))
        self.moves_text.configure(state="disabled")

        self.log_text = ctk.CTkTextbox(parent, wrap="word")
        self.log_text.grid(row=9, column=0, sticky="nsew", padx=18, pady=(0, 12))
        self.log_text.insert("1.0", "Ready.\n")
        self.log_text.configure(state="disabled")

        action_frame = ctk.CTkFrame(parent, fg_color="transparent")
        action_frame.grid(row=10, column=0, sticky="ew", padx=18, pady=(0, 18))
        action_frame.grid_columnconfigure((0, 1), weight=1)
        self.process_button = ctk.CTkButton(action_frame, text="Process File", height=42, command=self.process_file)
        self.process_button.grid(row=0, column=0, sticky="ew", padx=(0, 6))
        ctk.CTkButton(action_frame, text="Close", height=42, command=self.root.destroy).grid(
            row=0, column=1, sticky="ew", padx=(6, 0)
        )

        self.status_var = ctk.StringVar(value="Ready")
        ctk.CTkLabel(parent, textvariable=self.status_var, text_color="#a9b7c6").grid(
            row=11, column=0, sticky="w", padx=18, pady=(0, 14)
        )

        self.mode_var.trace_add("write", self.on_mode_change)
        self.on_mode_change()

    def set_chess_controls_enabled(self, enabled: bool) -> None:
        state = "normal" if enabled else "disabled"
        for row in getattr(self, "squares", []):
            for button in row:
                button.configure(state=state)
        if getattr(self, "reset_button", None):
            self.reset_button.configure(state=state)

    def on_mode_change(self, *_args) -> None:
        if getattr(self, "mode_var", None) is None:
            return

        if self.mode_var.get() == "decrypt":
            self.recipient_menu.configure(state="disabled")
            self.process_button.configure(text="Decrypt with RSA Private Key")

            if self.is_hybrid_v2_vault:
                self.set_chess_controls_enabled(False)
                self.chess_title_label.configure(text="RSA Private-Key Decryption")
                self.chess_hint_label.configure(
                    text="This is a hybrid vault. No chess moves are required for decryption.",
                    text_color="#d6b95f",
                )
                self.mode_explainer_label.configure(
                    text=(
                        "This file contains an AES key wrapped with your RSA public key. "
                        "Click decrypt, then your private key unlocks the AES key automatically."
                    )
                )
                self.manual_key_label.grid_remove()
                self.manual_key_entry.grid_remove()
                self.moves_label.grid_remove()
                self.moves_text.grid_remove()
            else:
                self.set_chess_controls_enabled(True)
                self.chess_title_label.configure(text="Legacy Chess-Key Decryption")
                self.chess_hint_label.configure(
                    text="Legacy vault detected. Re-enter the original chess moves or phrase.",
                    text_color="#ffcc66",
                )
                self.mode_explainer_label.configure(
                    text="This older vault was not RSA-wrapped, so it still needs the original chess secret."
                )
                self.manual_key_label.grid()
                self.manual_key_entry.grid()
                self.moves_label.grid()
                self.moves_text.grid()
                self.manual_key_entry.configure(
                    placeholder_text="Legacy only: enter the original chess phrase or rebuild the same board sequence."
                )
        else:
            self.recipient_menu.configure(state="normal")
            self.process_button.configure(text="Encrypt and Store Vault")
            self.set_chess_controls_enabled(True)
            self.chess_title_label.configure(text="Chess Key Builder")
            self.chess_hint_label.configure(
                text="Files: a-h  |  Ranks: 1-8  |  White moves first",
                text_color="#b8c2cc",
            )
            self.mode_explainer_label.configure(
                text=(
                    "Encryption: chess moves help generate a fresh AES key, then that AES key is encrypted "
                    "with the recipient's RSA public key. Decryption does not require sharing the chess sequence."
                )
            )
            self.manual_key_label.grid()
            self.manual_key_entry.grid()
            self.moves_label.grid()
            self.moves_text.grid()
            self.manual_key_entry.configure(
                placeholder_text="Optional chess phrase, for example: WN:g1-f3 BP:e7-e5 ..."
            )

    def update_board_display(self) -> None:
        for row in range(8):
            for col in range(8):
                piece = self.board[row][col]
                button = self.squares[row][col]
                color = "#d6b95f" if self.selected_square == (row, col) else self.square_color(row, col)
                text_color = "#111111" if (row + col) % 2 == 0 else "#ffffff"
                button.configure(text=piece.symbol() if piece else "", fg_color=color, hover_color="#a7c7e7", text_color=text_color)

    def set_status(self, message: str) -> None:
        self.status_var.set(message)
        self.log(message)

    def log(self, message: str) -> None:
        self.log_text.configure(state="normal")
        self.log_text.insert("end", f"{utc_now()} - {message}\n")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def reset_board(self) -> None:
        self.setup_board()
        self.selected_square = None
        self.moves_sequence.clear()
        self.current_turn_is_white = True
        self.moves_text.configure(state="normal")
        self.moves_text.delete("1.0", "end")
        self.moves_text.configure(state="disabled")
        self.update_board_display()
        self.set_status("Board reset. New chess sequence started.")

    # ------------------------------------------------------------------
    # Crypto processing
    # ------------------------------------------------------------------
    def get_chess_secret(self) -> str:
        manual = self.manual_key_entry.get().strip()
        if manual:
            return "manual:" + manual
        return "board:" + " ".join(self.moves_sequence)

    def get_recipients(self) -> list[str]:
        recipients = {self.current_user}
        selected = self.recipient_var.get().strip()
        if selected:
            recipients.add(selected)
        return sorted(recipients)

    def make_output_path(self) -> Path:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        safe_user = sanitize_filename(self.current_user)
        safe_name = sanitize_filename(self.selected_file.name)
        return self.output_directory / f"{safe_user}__{timestamp}__{safe_name}.chessvault"

    def resolve_public_keys(self, recipients: list[str]) -> dict[str, str]:
        if not self.public_key_resolver:
            raise ValueError("Public key resolver is not configured.")
        public_keys = self.public_key_resolver(recipients)
        missing = [name for name in recipients if name not in public_keys or not public_keys[name]]
        if missing:
            raise ValueError("Missing public key for: " + ", ".join(missing))
        return public_keys

    @staticmethod
    def wrap_key_for_recipients(content_key: bytes, public_keys: dict[str, str]) -> list[dict]:
        encrypted_keys: list[dict] = []
        for username, pem in sorted(public_keys.items()):
            public_key = serialization.load_pem_public_key(pem.encode("utf-8"))
            wrapped = public_key.encrypt(
                content_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
            encrypted_keys.append(
                {
                    "username": username,
                    "algorithm": "RSA-OAEP-SHA256",
                    "wrapped_key": b64e(wrapped),
                }
            )
        return encrypted_keys

    def encrypt_file(self) -> Path:
        if not self.selected_file.exists():
            raise FileNotFoundError("Selected file does not exist.")
        if self.selected_file.suffix == ".chessvault":
            raise ValueError("This file already looks encrypted. Choose decrypt mode instead.")

        chess_secret = self.get_chess_secret()
        kdf_salt = secrets.token_bytes(SALT_SIZE)
        hkdf_salt = secrets.token_bytes(SALT_SIZE)
        nonce = secrets.token_bytes(NONCE_SIZE)
        random_seed = secrets.token_bytes(KEY_SIZE)

        chess_component = derive_chess_component(chess_secret, kdf_salt)
        content_key = make_hybrid_content_key(chess_component, random_seed, hkdf_salt)
        aesgcm = AESGCM(content_key)

        recipients = self.get_recipients()
        public_keys = self.resolve_public_keys(recipients)
        encrypted_keys = self.wrap_key_for_recipients(content_key, public_keys)

        metadata = {
            "version": VERSION,
            "algorithm": "AES-256-GCM",
            "key_management": "HYBRID_RSA_OAEP_SHA256",
            "kdf": "PBKDF2-HMAC-SHA256 + HKDF-SHA256",
            "iterations": KDF_ITERATIONS,
            "kdf_salt": b64e(kdf_salt),
            "hkdf_salt": b64e(hkdf_salt),
            "nonce": b64e(nonce),
            "sender": self.current_user,
            "owner": self.current_user,
            "recipients": recipients,
            "encrypted_keys": encrypted_keys,
            "original_filename": self.selected_file.name,
            "created_utc": utc_now(),
            "chess_fingerprint": hashlib.sha256(chess_component).hexdigest()[:24],
        }

        plaintext = self.selected_file.read_bytes()
        ciphertext = aesgcm.encrypt(nonce, plaintext, v2_aad(metadata))
        output_path = self.make_output_path()
        output_path.write_bytes(build_vault_blob(metadata, ciphertext))
        return output_path

    def find_wrapped_key(self, metadata: dict) -> str:
        encrypted_keys = metadata.get("encrypted_keys", [])
        for item in encrypted_keys:
            if item.get("username") == self.current_user:
                return item.get("wrapped_key", "")
        recipients = ", ".join(metadata.get("recipients", [])) or "none"
        raise ValueError(
            f"Your account is not a recipient for this vault. Allowed recipients: {recipients}"
        )

    def load_private_key(self):
        if not self.private_key_loader:
            raise ValueError("Private key loader is not configured.")
        return self.private_key_loader()

    def decrypt_hybrid_v2(self, metadata: dict, ciphertext: bytes) -> tuple[Path, dict]:
        wrapped_key_b64 = self.find_wrapped_key(metadata)
        private_key = self.load_private_key()
        content_key = private_key.decrypt(
            b64d(wrapped_key_b64),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        nonce = b64d(metadata["nonce"])
        aesgcm = AESGCM(content_key)
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, v2_aad(metadata))
        except InvalidTag as exc:
            raise ValueError("Decryption failed. The vault file was modified or the wrong private key was used.") from exc

        original_name = sanitize_filename(metadata.get("original_filename", "decrypted_document"))
        output_path = self.temp_dir / f"decrypted_{secrets.token_hex(6)}_{original_name}"
        output_path.write_bytes(plaintext)
        return output_path, metadata

    def decrypt_legacy_v1(self, metadata: dict, ciphertext: bytes) -> tuple[Path, dict]:
        salt = b64d(metadata["salt"])
        nonce = b64d(metadata["nonce"])
        iterations = int(metadata.get("iterations", KDF_ITERATIONS))
        key = derive_legacy_key(self.get_chess_secret(), salt, iterations)
        aesgcm = AESGCM(key)
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, legacy_v1_aad(metadata))
        except InvalidTag as exc:
            raise ValueError("Legacy decryption failed. Enter the original chess sequence/key phrase.") from exc

        original_name = sanitize_filename(metadata.get("original_filename", "decrypted_document"))
        output_path = self.temp_dir / f"legacy_decrypted_{secrets.token_hex(6)}_{original_name}"
        output_path.write_bytes(plaintext)
        return output_path, metadata

    def decrypt_file(self) -> tuple[Path, dict]:
        metadata, ciphertext, magic = parse_vault_blob(self.selected_file.read_bytes())
        if magic == MAGIC_V2 and metadata.get("key_management") == "HYBRID_RSA_OAEP_SHA256":
            return self.decrypt_hybrid_v2(metadata, ciphertext)
        return self.decrypt_legacy_v1(metadata, ciphertext)

    def process_file(self, *args, mode: str | None = None, **kwargs) -> str | None:
        selected_mode = mode or self.mode_var.get()
        try:
            if selected_mode == "encrypt":
                output_path = self.encrypt_file()
                self.set_status(f"Encryption complete: {output_path.name}")
                if self.on_complete:
                    self.on_complete(str(output_path), "encrypt", read_vault_metadata(output_path))
                return str(output_path)

            if selected_mode == "decrypt":
                output_path, metadata = self.decrypt_file()
                self.set_status(f"Decryption complete: {output_path.name}")
                if self.on_complete:
                    self.on_complete(str(output_path), "decrypt", metadata)
                return str(output_path)

            raise ValueError("Invalid mode selected.")
        except Exception as exc:
            self.set_status(str(exc))
            try:
                from tkinter import messagebox
                messagebox.showerror("Processing failed", str(exc))
            except Exception:
                pass
            return None


if __name__ == "__main__":
    root = ctk.CTk()
    demo_file = Path("example.txt")
    if not demo_file.exists():
        demo_file.write_text("Demo file for Chess Hybrid AES Processor.\n", encoding="utf-8")
    chess_encryption(root, str(demo_file), "spy_documents", "admin")
    root.mainloop()
