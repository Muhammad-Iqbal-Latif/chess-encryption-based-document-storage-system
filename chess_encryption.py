from __future__ import annotations

import atexit
import base64
import hashlib
import hmac
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Mapping, Sequence

import tkinter as tk
from tkinter import filedialog
from tkinter import font as tkfont

import customtkinter as ctk

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


VAULT_EXTENSION = ".chessvault"
VAULT_MAGIC = b"CHESSVAULT\x01"
HEADER_LENGTH = struct.Struct(">I")
FORMAT_VERSION = 1
KDF_ITERATIONS = 600_000
MINIMUM_MOVES = 8
MAX_HEADER_SIZE = 64 * 1024
SQUARE_PATTERN = re.compile(r"^[a-h][1-8]$")


class VaultFormatError(ValueError):
    """Raised when a file is not a valid ChessVault container."""


class MoveSequenceError(ValueError):
    """Raised when the replayed move sequence does not match the vault."""


@dataclass(frozen=True)
class VaultResult:
    vault_path: Path
    moves_path: Path
    original_filename: str
    move_count: int
    sequence_id: str


@dataclass(frozen=True)
class VaultContents:
    metadata: dict
    encrypted_token: bytes


def _normalise_move(move: Mapping[str, object], index: int) -> tuple[str, str]:
    try:
        source = str(move["from"]).strip().lower()
        destination = str(move["to"]).strip().lower()
    except KeyError as exc:
        raise ValueError(f"Move {index} is missing {exc.args[0]!r}.") from exc

    if not SQUARE_PATTERN.fullmatch(source) or not SQUARE_PATTERN.fullmatch(destination):
        raise ValueError(f"Move {index} contains an invalid chess coordinate.")
    if source == destination:
        raise ValueError(f"Move {index} has the same source and destination.")
    return source, destination


def canonicalise_moves(moves: Sequence[Mapping[str, object]]) -> bytes:
    """Return one deterministic byte representation of the ordered moves."""
    if len(moves) < MINIMUM_MOVES:
        raise MoveSequenceError(
            f"At least {MINIMUM_MOVES} valid moves are required; only {len(moves)} were entered."
        )

    canonical_lines = []
    for index, move in enumerate(moves, start=1):
        source, destination = _normalise_move(move, index)
        canonical_lines.append(f"{index:04d}:{source}>{destination}")
    return "\n".join(canonical_lines).encode("ascii")


def sequence_identifier(moves: Sequence[Mapping[str, object]]) -> str:
    return hashlib.sha256(canonicalise_moves(moves)).hexdigest()[:16].upper()


def derive_fernet_key(
    moves: Sequence[Mapping[str, object]],
    salt: bytes,
    iterations: int = KDF_ITERATIONS,
) -> bytes:
    if len(salt) != 16:
        raise ValueError("ChessVault salt must be exactly 16 bytes.")
    if iterations < 100_000:
        raise VaultFormatError("The vault contains an unsafe or invalid KDF iteration count.")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return base64.urlsafe_b64encode(kdf.derive(canonicalise_moves(moves)))


def _sanitise_component(value: str, fallback: str = "document") -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", value.strip())
    cleaned = cleaned.strip("._")
    return cleaned or fallback


def _unique_path(directory: Path, filename: str) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    candidate = directory / filename
    if not candidate.exists():
        return candidate

    path = Path(filename)
    suffixes = "".join(path.suffixes)
    stem = path.name[: -len(suffixes)] if suffixes else path.name
    counter = 2
    while True:
        candidate = directory / f"{stem}_{counter}{suffixes}"
        if not candidate.exists():
            return candidate
        counter += 1


def default_download_directory() -> Path:
    downloads = Path.home() / "Downloads"
    if downloads.is_dir() and os.access(downloads, os.W_OK):
        return downloads
    return Path.home()


def read_vault(vault_path: str | os.PathLike[str]) -> VaultContents:
    path = Path(vault_path)
    with path.open("rb") as handle:
        magic = handle.read(len(VAULT_MAGIC))
        if magic != VAULT_MAGIC:
            raise VaultFormatError("This is not a supported .chessvault file.")

        raw_length = handle.read(HEADER_LENGTH.size)
        if len(raw_length) != HEADER_LENGTH.size:
            raise VaultFormatError("The ChessVault header is incomplete.")

        header_size = HEADER_LENGTH.unpack(raw_length)[0]
        if not 1 <= header_size <= MAX_HEADER_SIZE:
            raise VaultFormatError("The ChessVault header size is invalid.")

        raw_header = handle.read(header_size)
        if len(raw_header) != header_size:
            raise VaultFormatError("The ChessVault metadata is incomplete.")

        try:
            metadata = json.loads(raw_header.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise VaultFormatError("The ChessVault metadata is corrupted.") from exc

        token = handle.read()

    required_fields = {
        "format",
        "version",
        "original_filename",
        "salt_b64",
        "kdf_iterations",
        "move_count",
        "sequence_id",
        "plaintext_sha256",
    }
    if not required_fields.issubset(metadata):
        raise VaultFormatError("The ChessVault metadata is missing required fields.")
    if metadata["format"] != "ChessVault" or metadata["version"] != FORMAT_VERSION:
        raise VaultFormatError("This ChessVault version is not supported.")
    if not token:
        raise VaultFormatError("The ChessVault encrypted payload is missing.")

    return VaultContents(metadata=metadata, encrypted_token=token)


def create_chessvault(
    source_path: str | os.PathLike[str],
    output_directory: str | os.PathLike[str],
    current_user: str,
    moves: Sequence[Mapping[str, object]],
    moves_directory: str | os.PathLike[str] | None = None,
) -> VaultResult:
    source = Path(source_path)
    if not source.is_file():
        raise FileNotFoundError(f"Document not found: {source}")

    canonicalise_moves(moves)
    sequence_id = sequence_identifier(moves)
    salt = os.urandom(16)
    key = derive_fernet_key(moves, salt, KDF_ITERATIONS)
    plaintext = source.read_bytes()
    encrypted_token = Fernet(key).encrypt(plaintext)

    owner = _sanitise_component(current_user, "user")
    document_stem = _sanitise_component(source.stem, "document")
    vault_name = f"{owner}_{document_stem}{VAULT_EXTENSION}"
    vault_path = _unique_path(Path(output_directory), vault_name)

    metadata = {
        "format": "ChessVault",
        "version": FORMAT_VERSION,
        "original_filename": source.name,
        "owner": current_user,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "encryption": "Fernet",
        "kdf": "PBKDF2-HMAC-SHA256",
        "kdf_iterations": KDF_ITERATIONS,
        "salt_b64": base64.urlsafe_b64encode(salt).decode("ascii"),
        "move_count": len(moves),
        "sequence_id": sequence_id,
        "plaintext_sha256": hashlib.sha256(plaintext).hexdigest(),
    }
    raw_header = json.dumps(
        metadata,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    if len(raw_header) > MAX_HEADER_SIZE:
        raise ValueError("The generated ChessVault metadata is unexpectedly large.")

    vault_path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = vault_path.with_name(f".{vault_path.name}.tmp-{os.getpid()}")
    try:
        with temp_path.open("wb") as handle:
            handle.write(VAULT_MAGIC)
            handle.write(HEADER_LENGTH.pack(len(raw_header)))
            handle.write(raw_header)
            handle.write(encrypted_token)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, vault_path)
    finally:
        temp_path.unlink(missing_ok=True)

    move_output_directory = Path(moves_directory) if moves_directory else default_download_directory()
    moves_name = f"{vault_path.stem}_moves.txt"
    moves_path = _unique_path(move_output_directory, moves_name)
    _write_move_instructions(moves_path, vault_path.name, source.name, moves, sequence_id)

    return VaultResult(
        vault_path=vault_path,
        moves_path=moves_path,
        original_filename=source.name,
        move_count=len(moves),
        sequence_id=sequence_id,
    )


def _write_move_instructions(
    output_path: Path,
    vault_filename: str,
    original_filename: str,
    moves: Sequence[Mapping[str, object]],
    sequence_id: str,
) -> None:
    lines = [
        "CHESSVAULT MOVE INSTRUCTIONS",
        "=" * 34,
        f"Vault file: {vault_filename}",
        f"Original document: {original_filename}",
        f"Move count: {len(moves)}",
        f"Sequence ID: {sequence_id}",
        "Starting position: Standard ChessVault board; White moves first.",
        "",
        "Replay every move below in exactly this order:",
        "",
    ]

    for index, move in enumerate(moves, start=1):
        source, destination = _normalise_move(move, index)
        piece_name = str(move.get("piece_name", "Piece")).strip() or "Piece"
        side = str(move.get("side", "")).strip()
        label = f"{side} {piece_name}".strip()
        lines.append(f"{index:02d}. {source} -> {destination}    [{label}]")

    lines.extend(
        [
            "",
            "Important:",
            "- Use the matching .chessvault file.",
            "- Begin from a reset board.",
            "- Perform every move exactly once and in the listed order.",
            "- A missing, extra, or different move will prevent decryption.",
            "- This TXT file contains the decryption move sequence; share it only with the intended recipient.",
        ]
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def decrypt_chessvault(
    vault_path: str | os.PathLike[str],
    moves: Sequence[Mapping[str, object]],
) -> tuple[dict, bytes]:
    contents = read_vault(vault_path)
    metadata = contents.metadata

    expected_count = int(metadata["move_count"])
    if len(moves) != expected_count:
        raise MoveSequenceError(
            f"This vault requires exactly {expected_count} moves; {len(moves)} were entered."
        )

    actual_sequence_id = sequence_identifier(moves)
    if actual_sequence_id != str(metadata["sequence_id"]):
        raise MoveSequenceError("The entered chess moves do not match this vault.")

    try:
        salt = base64.urlsafe_b64decode(str(metadata["salt_b64"]).encode("ascii"))
        iterations = int(metadata["kdf_iterations"])
    except (ValueError, TypeError, base64.binascii.Error) as exc:
        raise VaultFormatError("The ChessVault KDF metadata is invalid.") from exc

    key = derive_fernet_key(moves, salt, iterations)
    try:
        plaintext = Fernet(key).decrypt(contents.encrypted_token)
    except InvalidToken as exc:
        raise MoveSequenceError(
            "Decryption failed. The move sequence is wrong or the vault has been modified."
        ) from exc

    expected_hash = str(metadata["plaintext_sha256"])
    if not hmac.compare_digest(hashlib.sha256(plaintext).hexdigest(), expected_hash):
        raise VaultFormatError("The decrypted document failed its integrity check.")

    return metadata, plaintext


def open_with_default_application(path: Path) -> None:
    if sys.platform.startswith("win"):
        os.startfile(str(path))  # type: ignore[attr-defined]
        return
    if sys.platform == "darwin":
        subprocess.Popen(["open", str(path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return

    opener = shutil.which("xdg-open")
    if not opener:
        raise RuntimeError("No desktop file opener was found. Use Download Document instead.")
    subprocess.Popen([opener, str(path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


class ChessPiece:
    """Represents one chess piece and its colour."""

    PIECE_NAMES = {
        "P": "Pawn",
        "R": "Rook",
        "N": "Knight",
        "B": "Bishop",
        "Q": "Queen",
        "K": "King",
    }

    def __init__(self, piece_type: str, is_white: bool):
        self.piece_type = piece_type
        self.is_white = is_white

    @property
    def name(self) -> str:
        return self.PIECE_NAMES[self.piece_type]

    @property
    def side(self) -> str:
        return "White" if self.is_white else "Black"

    def __str__(self) -> str:
        symbols = {
            "P": "♙" if self.is_white else "♟",
            "R": "♖" if self.is_white else "♜",
            "N": "♘" if self.is_white else "♞",
            "B": "♗" if self.is_white else "♝",
            "Q": "♕" if self.is_white else "♛",
            "K": "♔" if self.is_white else "♚",
        }
        return symbols.get(self.piece_type, " ")


from ui_theme import (
    COLORS,
    apply_window_icon,
    center_window,
    font,
    format_bytes,
    logo_image,
    mono_font,
    primary_button,
    secondary_button,
    show_dialog,
)


class ChessEncryptionWindow:
    """Premium chess-sequence console for creating and unlocking ChessVault files."""

    def __init__(
        self,
        root: tk.Misc,
        selected_file: str | os.PathLike[str],
        app_output_directory: str | os.PathLike[str],
        current_user: str,
        operation: str = "encrypt",
        on_encrypted: Callable[[VaultResult], None] | None = None,
    ):
        if operation not in {"encrypt", "decrypt"}:
            raise ValueError("operation must be 'encrypt' or 'decrypt'")

        self.root = root
        self.selected_file = str(selected_file)
        self.output_directory = Path(app_output_directory)
        self.current_user = current_user
        self.operation = operation
        self.on_encrypted = on_encrypted
        self.selected_square: tuple[int, int] | None = None
        self.hover_square: tuple[int, int] | None = None
        self.last_move: tuple[tuple[int, int], tuple[int, int]] | None = None
        self.moves_sequence: list[dict[str, str]] = []
        self.current_turn = True
        self._temporary_view_directories: list[Path] = []
        self.vault_metadata: dict | None = None
        self.board_origin = (0.0, 0.0)
        self.square_size = 0.0
        self._clock_after_id: str | None = None

        self.root.title("ChessVault — Create Secure Vault" if operation == "encrypt" else "ChessVault — Unlock Document")
        self.root.configure(fg_color=COLORS["background"])
        self.root.minsize(1100, 720)
        parent = self.root.master if isinstance(self.root.master, tk.Misc) else None
        center_window(self.root, 1380, 850, parent)
        apply_window_icon(self.root)
        self.root.protocol("WM_DELETE_WINDOW", self.close_window)
        self.output_directory.mkdir(parents=True, exist_ok=True)

        if operation == "decrypt":
            self.vault_metadata = read_vault(self.selected_file).metadata

        self.setup_board()
        self.setup_gui()
        self.update_clock()

    # ------------------------------------------------------------------
    # Board model
    # ------------------------------------------------------------------
    def setup_board(self) -> None:
        self.board: list[list[ChessPiece | None]] = [[None for _ in range(8)] for _ in range(8)]
        for col in range(8):
            self.board[1][col] = ChessPiece("P", True)
            self.board[6][col] = ChessPiece("P", False)

        piece_order = ["R", "N", "B", "Q", "K", "B", "N", "R"]
        for col, piece_type in enumerate(piece_order):
            self.board[0][col] = ChessPiece(piece_type, True)
            self.board[7][col] = ChessPiece(piece_type, False)

    # ------------------------------------------------------------------
    # Premium window layout
    # ------------------------------------------------------------------
    def setup_gui(self) -> None:
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_rowconfigure(1, weight=1)

        self._build_header()

        workspace = ctk.CTkFrame(self.root, fg_color="transparent")
        workspace.grid(row=1, column=0, sticky="nsew", padx=24, pady=(0, 18))
        workspace.grid_columnconfigure(0, weight=7, uniform="workspace")
        workspace.grid_columnconfigure(1, weight=5, uniform="workspace")
        workspace.grid_rowconfigure(0, weight=1)

        board_panel = ctk.CTkFrame(
            workspace,
            fg_color=COLORS["surface"],
            corner_radius=22,
            border_width=1,
            border_color=COLORS["border_soft"],
        )
        board_panel.grid(row=0, column=0, sticky="nsew", padx=(0, 9))
        board_panel.grid_rowconfigure(1, weight=1)
        board_panel.grid_columnconfigure(0, weight=1)
        self.setup_chess_board(board_panel)

        control_panel = ctk.CTkFrame(
            workspace,
            fg_color=COLORS["surface"],
            corner_radius=22,
            border_width=1,
            border_color=COLORS["border_soft"],
        )
        control_panel.grid(row=0, column=1, sticky="nsew", padx=(9, 0))
        control_panel.grid_columnconfigure(0, weight=1)
        control_panel.grid_rowconfigure(3, weight=1)
        self.setup_control_panel(control_panel)

        status_bar = ctk.CTkFrame(
            self.root,
            fg_color=COLORS["surface"],
            corner_radius=12,
            border_width=1,
            border_color=COLORS["border_soft"],
        )
        status_bar.grid(row=2, column=0, sticky="ew", padx=24, pady=(0, 18))
        status_bar.grid_columnconfigure(0, weight=1)
        self.status_var = tk.StringVar(value="Ready")
        ctk.CTkLabel(
            status_bar,
            textvariable=self.status_var,
            text_color=COLORS["text_secondary"],
            font=font(10),
            anchor="w",
        ).grid(row=0, column=0, sticky="ew", padx=14, pady=8)
        self.time_label = ctk.CTkLabel(
            status_bar,
            text="",
            text_color=COLORS["text_muted"],
            font=mono_font(9),
            anchor="e",
        )
        self.time_label.grid(row=0, column=1, sticky="e", padx=14, pady=8)

        self.update_move_status()
        self.render_move_timeline()
        self.log_move("Secure chess console initialized. White moves first.")

    def _build_header(self) -> None:
        header = ctk.CTkFrame(self.root, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=24, pady=(20, 16))
        header.grid_columnconfigure(1, weight=1)

        image = logo_image(46)
        header.logo_reference = image
        ctk.CTkLabel(header, text="", image=image).grid(row=0, column=0, rowspan=2, padx=(0, 13))

        title_text = "Create encrypted vault" if self.operation == "encrypt" else "Unlock encrypted document"
        ctk.CTkLabel(
            header,
            text=title_text,
            text_color=COLORS["text"],
            font=font(24, "bold"),
            anchor="w",
        ).grid(row=0, column=1, sticky="sw")
        ctk.CTkLabel(
            header,
            text=Path(self.selected_file).name,
            text_color=COLORS["text_muted"],
            font=mono_font(10),
            anchor="w",
        ).grid(row=1, column=1, sticky="nw", pady=(3, 0))

        accent = COLORS["cyan"] if self.operation == "encrypt" else COLORS["gold"]
        accent_dark = COLORS["cyan_dark"] if self.operation == "encrypt" else COLORS["gold_dark"]
        badge_text = "SENDER MODE" if self.operation == "encrypt" else "RECIPIENT MODE"
        ctk.CTkLabel(
            header,
            text=badge_text,
            fg_color=accent_dark,
            text_color=accent,
            corner_radius=11,
            height=34,
            font=mono_font(9, "bold"),
        ).grid(row=0, column=2, rowspan=2, sticky="e", padx=(12, 0), ipadx=13)

    def setup_chess_board(self, parent: tk.Misc) -> None:
        heading = ctk.CTkFrame(parent, fg_color="transparent")
        heading.grid(row=0, column=0, sticky="ew", padx=22, pady=(19, 8))
        heading.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            heading,
            text="Sequence board",
            text_color=COLORS["text"],
            font=font(16, "bold"),
            anchor="w",
        ).grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(
            heading,
            text="Select a piece, then select its destination",
            text_color=COLORS["text_muted"],
            font=font(10),
            anchor="e",
        ).grid(row=0, column=1, sticky="e")

        board_shell = ctk.CTkFrame(
            parent,
            fg_color=COLORS["background_2"],
            corner_radius=18,
            border_width=1,
            border_color=COLORS["border"],
        )
        board_shell.grid(row=1, column=0, sticky="nsew", padx=20, pady=8)
        board_shell.grid_rowconfigure(0, weight=1)
        board_shell.grid_columnconfigure(0, weight=1)

        self.board_canvas = tk.Canvas(
            board_shell,
            bg=COLORS["background_2"],
            highlightthickness=0,
            bd=0,
            cursor="hand2",
        )
        self.board_canvas.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        self.board_canvas.bind("<Configure>", self.draw_board)
        self.board_canvas.bind("<Button-1>", self.on_canvas_click)
        self.board_canvas.bind("<Motion>", self.on_canvas_motion)
        self.board_canvas.bind("<Leave>", self.on_canvas_leave)

        families = set(tkfont.families(self.root))
        self.piece_font_family = next(
            (candidate for candidate in ("DejaVu Sans", "Segoe UI Symbol", "Arial Unicode MS", "Noto Sans Symbols 2") if candidate in families),
            "Arial",
        )

        footer = ctk.CTkFrame(parent, fg_color="transparent")
        footer.grid(row=2, column=0, sticky="ew", padx=22, pady=(6, 17))
        footer.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            footer,
            text="● Legal destinations appear after selecting a piece",
            text_color=COLORS["text_muted"],
            font=font(9),
            anchor="w",
        ).grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(
            footer,
            text="WHITE MOVES FIRST",
            text_color=COLORS["cyan"],
            font=mono_font(9, "bold"),
            anchor="e",
        ).grid(row=0, column=1, sticky="e")

    def setup_control_panel(self, parent: tk.Misc) -> None:
        self._build_file_card(parent)
        self._build_progress_card(parent)
        self._build_control_row(parent)
        self._build_timeline_tabs(parent)
        self._build_action_area(parent)

    def _build_file_card(self, parent: tk.Misc) -> None:
        card = ctk.CTkFrame(
            parent,
            fg_color=COLORS["background_2"],
            corner_radius=16,
            border_width=1,
            border_color=COLORS["border_soft"],
        )
        card.grid(row=0, column=0, sticky="ew", padx=18, pady=(18, 8))
        card.grid_columnconfigure(1, weight=1)

        icon_text = "♜" if self.operation == "encrypt" else "♞"
        accent = COLORS["cyan"] if self.operation == "encrypt" else COLORS["gold"]
        accent_dark = COLORS["cyan_dark"] if self.operation == "encrypt" else COLORS["gold_dark"]
        ctk.CTkLabel(
            card,
            text=icon_text,
            width=52,
            height=52,
            corner_radius=14,
            fg_color=accent_dark,
            text_color=accent,
            font=font(25, "bold"),
        ).grid(row=0, column=0, rowspan=3, padx=14, pady=14)

        if self.operation == "encrypt":
            original_name = Path(self.selected_file).name
            summary = "A .chessvault and ordered move TXT will be produced."
            secondary = f"Source size: {format_bytes(Path(self.selected_file).stat().st_size)}"
        else:
            assert self.vault_metadata is not None
            original_name = str(self.vault_metadata["original_filename"])
            summary = f"Replay exactly {self.vault_metadata['move_count']} moves from the sender's TXT."
            secondary = f"Sequence ID: {self.vault_metadata['sequence_id']}"

        ctk.CTkLabel(card, text=original_name, text_color=COLORS["text"], font=font(12, "bold"), anchor="w", wraplength=360).grid(row=0, column=1, sticky="sew", pady=(14, 1), padx=(0, 12))
        ctk.CTkLabel(card, text=summary, text_color=COLORS["text_secondary"], font=font(9), anchor="w", wraplength=390).grid(row=1, column=1, sticky="new", padx=(0, 12))
        ctk.CTkLabel(card, text=secondary, text_color=accent, font=mono_font(8, "bold"), anchor="w").grid(row=2, column=1, sticky="nw", pady=(4, 14), padx=(0, 12))

    def _build_progress_card(self, parent: tk.Misc) -> None:
        card = ctk.CTkFrame(
            parent,
            fg_color=COLORS["background_2"],
            corner_radius=16,
            border_width=1,
            border_color=COLORS["border_soft"],
        )
        card.grid(row=1, column=0, sticky="ew", padx=18, pady=8)
        card.grid_columnconfigure(0, weight=1)

        top = ctk.CTkFrame(card, fg_color="transparent")
        top.grid(row=0, column=0, sticky="ew", padx=15, pady=(14, 7))
        top.grid_columnconfigure(0, weight=1)
        self.move_count_var = tk.StringVar()
        self.turn_var = tk.StringVar()
        ctk.CTkLabel(top, textvariable=self.move_count_var, text_color=COLORS["text"], font=font(12, "bold"), anchor="w").grid(row=0, column=0, sticky="w")
        self.ready_badge = ctk.CTkLabel(
            top,
            text="BUILDING",
            fg_color=COLORS["warning_dark"],
            text_color=COLORS["warning"],
            corner_radius=9,
            height=27,
            font=mono_font(8, "bold"),
        )
        self.ready_badge.grid(row=0, column=1, sticky="e", ipadx=9)

        self.progress_bar = ctk.CTkProgressBar(
            card,
            height=8,
            corner_radius=4,
            fg_color=COLORS["surface_3"],
            progress_color=COLORS["cyan"],
        )
        self.progress_bar.grid(row=1, column=0, sticky="ew", padx=15, pady=4)
        self.progress_bar.set(0)

        bottom = ctk.CTkFrame(card, fg_color="transparent")
        bottom.grid(row=2, column=0, sticky="ew", padx=15, pady=(6, 14))
        bottom.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(bottom, textvariable=self.turn_var, text_color=COLORS["text_muted"], font=font(9), anchor="w").grid(row=0, column=0, sticky="w")
        self.sequence_preview_var = tk.StringVar(value="Sequence: pending")
        ctk.CTkLabel(bottom, textvariable=self.sequence_preview_var, text_color=COLORS["text_muted"], font=mono_font(8), anchor="e").grid(row=0, column=1, sticky="e")

    def _build_control_row(self, parent: tk.Misc) -> None:
        controls = ctk.CTkFrame(parent, fg_color="transparent")
        controls.grid(row=2, column=0, sticky="ew", padx=18, pady=7)
        controls.grid_columnconfigure((0, 1, 2), weight=1, uniform="control")

        self.undo_button = secondary_button(controls, "↶  Undo move", self.undo_last_move)
        self.undo_button.grid(row=0, column=0, sticky="ew", padx=(0, 5))
        secondary_button(controls, "⟳  Reset board", self.reset_board).grid(row=0, column=1, sticky="ew", padx=5)
        if self.operation == "decrypt":
            secondary_button(controls, "TXT  Open moves", self.open_move_text).grid(row=0, column=2, sticky="ew", padx=(5, 0))
        else:
            ctk.CTkLabel(
                controls,
                text=f"MIN {MINIMUM_MOVES} MOVES",
                height=42,
                corner_radius=12,
                fg_color=COLORS["surface_2"],
                text_color=COLORS["text_muted"],
                font=mono_font(9, "bold"),
            ).grid(row=0, column=2, sticky="ew", padx=(5, 0))

    def _build_timeline_tabs(self, parent: tk.Misc) -> None:
        self.tabview = ctk.CTkTabview(
            parent,
            fg_color=COLORS["background_2"],
            segmented_button_fg_color=COLORS["surface_2"],
            segmented_button_selected_color=COLORS["cyan_dark"],
            segmented_button_selected_hover_color=COLORS["cyan_dark"],
            segmented_button_unselected_color=COLORS["surface_2"],
            segmented_button_unselected_hover_color=COLORS["surface_hover"],
            text_color=COLORS["text_secondary"],
            corner_radius=16,
            border_width=1,
            border_color=COLORS["border_soft"],
        )
        self.tabview.grid(row=3, column=0, sticky="nsew", padx=18, pady=8)
        timeline_tab = self.tabview.add("Move timeline")
        activity_tab = self.tabview.add("Activity")
        timeline_tab.grid_rowconfigure(0, weight=1)
        timeline_tab.grid_columnconfigure(0, weight=1)
        activity_tab.grid_rowconfigure(0, weight=1)
        activity_tab.grid_columnconfigure(0, weight=1)

        self.move_scroll = ctk.CTkScrollableFrame(
            timeline_tab,
            fg_color="transparent",
            corner_radius=0,
            scrollbar_button_color=COLORS["surface_3"],
            scrollbar_button_hover_color=COLORS["cyan_dark"],
        )
        self.move_scroll.grid(row=0, column=0, sticky="nsew", padx=3, pady=3)
        self.move_scroll.grid_columnconfigure(0, weight=1)

        self.log_text = ctk.CTkTextbox(
            activity_tab,
            fg_color="transparent",
            text_color=COLORS["text_secondary"],
            font=mono_font(10),
            wrap="word",
            corner_radius=0,
            border_width=0,
        )
        self.log_text.grid(row=0, column=0, sticky="nsew", padx=7, pady=7)
        self.log_text.configure(state="disabled")

    def _build_action_area(self, parent: tk.Misc) -> None:
        area = ctk.CTkFrame(parent, fg_color="transparent")
        area.grid(row=4, column=0, sticky="ew", padx=18, pady=(7, 18))
        area.grid_columnconfigure((0, 1), weight=1, uniform="action")

        if self.operation == "encrypt":
            self.encrypt_button = primary_button(
                area,
                "Encrypt document + generate move TXT",
                self.encrypt_document,
            )
            self.encrypt_button.grid(row=0, column=0, columnspan=2, sticky="ew")
            self.encrypt_button.configure(state="disabled")
        else:
            self.view_button = primary_button(area, "Decrypt and view", self.decrypt_and_view)
            self.view_button.grid(row=0, column=0, sticky="ew", padx=(0, 5))
            self.download_button = ctk.CTkButton(
                area,
                text="Decrypt and download",
                command=self.decrypt_and_download,
                height=44,
                corner_radius=12,
                fg_color=COLORS["gold"],
                hover_color=COLORS["gold_hover"],
                text_color=COLORS["void"],
                font=font(12, "bold"),
            )
            self.download_button.grid(row=0, column=1, sticky="ew", padx=(5, 0))
            self.view_button.configure(state="disabled")
            self.download_button.configure(state="disabled")

    # ------------------------------------------------------------------
    # Responsive chessboard canvas
    # ------------------------------------------------------------------
    def draw_board(self, _event: tk.Event | None = None) -> None:
        if not hasattr(self, "board_canvas"):
            return
        canvas = self.board_canvas
        canvas.delete("all")
        width = max(120, canvas.winfo_width())
        height = max(120, canvas.winfo_height())
        self.square_size = max(20.0, min((width - 62) / 8.0, (height - 62) / 8.0))
        board_size = self.square_size * 8
        origin_x = (width - board_size) / 2
        origin_y = (height - board_size) / 2
        self.board_origin = (origin_x, origin_y)

        valid_targets = set(self.get_valid_targets()) if self.selected_square else set()
        last_squares = set(self.last_move) if self.last_move else set()

        canvas.create_rectangle(
            origin_x - 8,
            origin_y - 8,
            origin_x + board_size + 8,
            origin_y + board_size + 8,
            fill="#07101B",
            outline=COLORS["border"],
            width=2,
        )

        for row in range(8):
            for col in range(8):
                x1 = origin_x + col * self.square_size
                y1 = origin_y + row * self.square_size
                x2 = x1 + self.square_size
                y2 = y1 + self.square_size
                base = COLORS["white_square"] if (row + col) % 2 == 0 else COLORS["black_square"]
                if (row, col) == self.hover_square:
                    base = COLORS["white_square_hover"] if (row + col) % 2 == 0 else COLORS["black_square_hover"]
                if (row, col) in last_squares:
                    base = COLORS["last_move"]
                if (row, col) == self.selected_square:
                    base = COLORS["selection"]
                canvas.create_rectangle(x1, y1, x2, y2, fill=base, outline=base)

                if (row, col) in valid_targets:
                    target = self.board[row][col]
                    if target is None:
                        radius = self.square_size * 0.10
                        cx, cy = (x1 + x2) / 2, (y1 + y2) / 2
                        canvas.create_oval(cx - radius, cy - radius, cx + radius, cy + radius, fill=COLORS["legal_move"], outline="")
                    else:
                        inset = self.square_size * 0.08
                        canvas.create_oval(x1 + inset, y1 + inset, x2 - inset, y2 - inset, outline=COLORS["legal_move"], width=max(3, int(self.square_size * 0.06)))

                piece = self.board[row][col]
                if piece is not None:
                    cx, cy = (x1 + x2) / 2, (y1 + y2) / 2
                    piece_size = max(20, int(self.square_size * 0.58))
                    shadow_colour = "#243140" if piece.is_white else "#8394A5"
                    piece_colour = "#F8FBFD" if piece.is_white else "#07101A"
                    canvas.create_text(cx + 1.5, cy + 2.0, text=str(piece), font=(self.piece_font_family, piece_size), fill=shadow_colour)
                    canvas.create_text(cx, cy, text=str(piece), font=(self.piece_font_family, piece_size), fill=piece_colour)

        for index in range(8):
            file_x = origin_x + (index + 0.5) * self.square_size
            rank_y = origin_y + (index + 0.5) * self.square_size
            canvas.create_text(file_x, origin_y + board_size + 18, text=chr(97 + index).upper(), fill=COLORS["text_muted"], font=("Consolas", 9, "bold"))
            canvas.create_text(origin_x - 20, rank_y, text=str(8 - index), fill=COLORS["text_muted"], font=("Consolas", 9, "bold"))

    def canvas_square(self, x: float, y: float) -> tuple[int, int] | None:
        origin_x, origin_y = self.board_origin
        if self.square_size <= 0:
            return None
        col = int((x - origin_x) // self.square_size)
        row = int((y - origin_y) // self.square_size)
        if 0 <= row < 8 and 0 <= col < 8:
            return row, col
        return None

    def on_canvas_click(self, event: tk.Event) -> None:
        square = self.canvas_square(event.x, event.y)
        if square is not None:
            self.on_square_click(*square)

    def on_canvas_motion(self, event: tk.Event) -> None:
        square = self.canvas_square(event.x, event.y)
        if square != self.hover_square:
            self.hover_square = square
            self.draw_board()

    def on_canvas_leave(self, _event: tk.Event) -> None:
        if self.hover_square is not None:
            self.hover_square = None
            self.draw_board()

    def get_valid_targets(self) -> list[tuple[int, int]]:
        if self.selected_square is None:
            return []
        from_row, from_col = self.selected_square
        return [
            (row, col)
            for row in range(8)
            for col in range(8)
            if (row, col) != self.selected_square and self.is_valid_move(from_row, from_col, row, col)
        ]

    # ------------------------------------------------------------------
    # Move validation and entry
    # ------------------------------------------------------------------
    def is_valid_move(self, from_row: int, from_col: int, to_row: int, to_col: int) -> bool:
        piece = self.board[from_row][from_col]
        if not piece or piece.is_white != self.current_turn:
            return False

        target = self.board[to_row][to_col]
        if target and target.is_white == piece.is_white:
            return False

        row_diff = to_row - from_row
        col_diff = to_col - from_col

        if piece.piece_type == "P":
            direction = 1 if piece.is_white else -1
            starting_row = 1 if piece.is_white else 6
            if col_diff == 0 and row_diff == direction:
                return target is None
            if col_diff == 0 and row_diff == 2 * direction and from_row == starting_row:
                between_row = from_row + direction
                return target is None and self.board[between_row][from_col] is None
            if abs(col_diff) == 1 and row_diff == direction:
                return target is not None and target.is_white != piece.is_white
            return False

        if piece.piece_type == "R":
            return (row_diff == 0 or col_diff == 0) and self.is_path_clear(from_row, from_col, to_row, to_col)
        if piece.piece_type == "N":
            return (abs(row_diff), abs(col_diff)) in {(2, 1), (1, 2)}
        if piece.piece_type == "B":
            return abs(row_diff) == abs(col_diff) and self.is_path_clear(from_row, from_col, to_row, to_col)
        if piece.piece_type == "Q":
            valid_direction = row_diff == 0 or col_diff == 0 or abs(row_diff) == abs(col_diff)
            return valid_direction and self.is_path_clear(from_row, from_col, to_row, to_col)
        if piece.piece_type == "K":
            return max(abs(row_diff), abs(col_diff)) == 1
        return False

    def is_path_clear(self, from_row: int, from_col: int, to_row: int, to_col: int) -> bool:
        row_step = 0 if from_row == to_row else (1 if to_row > from_row else -1)
        col_step = 0 if from_col == to_col else (1 if to_col > from_col else -1)
        row, col = from_row + row_step, from_col + col_step
        while (row, col) != (to_row, to_col):
            if self.board[row][col] is not None:
                return False
            row += row_step
            col += col_step
        return True

    def on_square_click(self, row: int, col: int) -> None:
        if self.selected_square is None:
            piece = self.board[row][col]
            if piece is None:
                return
            if piece.is_white != self.current_turn:
                self.log_move(f"Rejected selection: it is {'White' if self.current_turn else 'Black'}'s turn.")
                self.status_var.set(f"Select a {'White' if self.current_turn else 'Black'} piece.")
                return
            self.selected_square = (row, col)
            self.draw_board()
            return

        from_row, from_col = self.selected_square
        if (from_row, from_col) == (row, col):
            self.selected_square = None
            self.draw_board()
            return

        target_piece = self.board[row][col]
        if target_piece is not None and target_piece.is_white == self.current_turn:
            self.selected_square = (row, col)
            self.draw_board()
            return

        if not self.is_valid_move(from_row, from_col, row, col):
            source = self.indices_to_square(from_row, from_col)
            destination = self.indices_to_square(row, col)
            self.log_move(f"Invalid move rejected: {source} → {destination}")
            self.status_var.set(f"Invalid move: {source} → {destination}")
            self.selected_square = None
            self.draw_board()
            return

        piece = self.board[from_row][from_col]
        assert piece is not None
        source = self.indices_to_square(from_row, from_col)
        destination = self.indices_to_square(row, col)
        self.moves_sequence.append(
            {
                "from": source,
                "to": destination,
                "piece_name": piece.name,
                "side": piece.side,
            }
        )
        self.board[row][col] = piece
        self.board[from_row][from_col] = None
        self.current_turn = not self.current_turn
        self.selected_square = None
        self.last_move = ((from_row, from_col), (row, col))

        self.log_move(f"{len(self.moves_sequence):02d}. {source} → {destination}  [{piece.side} {piece.name}]")
        self.draw_board()
        self.render_move_timeline()
        self.update_move_status()

    @staticmethod
    def indices_to_square(row: int, col: int) -> str:
        return f"{chr(97 + col)}{8 - row}"

    @staticmethod
    def square_to_indices(square: str) -> tuple[int, int]:
        if not SQUARE_PATTERN.fullmatch(square):
            raise ValueError(f"Invalid square: {square}")
        col = ord(square[0]) - ord("a")
        row = 8 - int(square[1])
        return row, col

    # ------------------------------------------------------------------
    # Timeline, status, and board controls
    # ------------------------------------------------------------------
    def render_move_timeline(self) -> None:
        if not hasattr(self, "move_scroll"):
            return
        for widget in self.move_scroll.winfo_children():
            widget.destroy()

        if not self.moves_sequence:
            empty = ctk.CTkFrame(self.move_scroll, fg_color="transparent")
            empty.grid(row=0, column=0, sticky="nsew", pady=28)
            ctk.CTkLabel(empty, text="♙", text_color=COLORS["text_muted"], font=font(30)).pack()
            ctk.CTkLabel(empty, text="No moves entered", text_color=COLORS["text_secondary"], font=font(12, "bold")).pack(pady=(6, 2))
            ctk.CTkLabel(empty, text="The ordered sequence will appear here.", text_color=COLORS["text_muted"], font=font(9)).pack()
            return

        for index, move in enumerate(self.moves_sequence, start=1):
            row = ctk.CTkFrame(
                self.move_scroll,
                fg_color=COLORS["surface_2"] if index % 2 else COLORS["surface"],
                corner_radius=11,
                border_width=1,
                border_color=COLORS["border_soft"],
            )
            row.grid(row=index - 1, column=0, sticky="ew", padx=2, pady=3)
            row.grid_columnconfigure(1, weight=1)
            ctk.CTkLabel(
                row,
                text=f"{index:02d}",
                width=34,
                height=34,
                corner_radius=10,
                fg_color=COLORS["cyan_dark"] if index % 2 else COLORS["gold_dark"],
                text_color=COLORS["cyan"] if index % 2 else COLORS["gold"],
                font=mono_font(9, "bold"),
            ).grid(row=0, column=0, padx=8, pady=7)
            ctk.CTkLabel(
                row,
                text=f"{move['from'].upper()}  →  {move['to'].upper()}",
                text_color=COLORS["text"],
                font=mono_font(11, "bold"),
                anchor="w",
            ).grid(row=0, column=1, sticky="ew")
            ctk.CTkLabel(
                row,
                text=f"{move['side']} {move['piece_name']}",
                text_color=COLORS["text_muted"],
                font=font(9),
                anchor="e",
            ).grid(row=0, column=2, padx=(8, 11), sticky="e")

    def log_move(self, message: str) -> None:
        if not hasattr(self, "log_text"):
            return
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.configure(state="normal")
        self.log_text.insert(tk.END, f"[{timestamp}]  {message}\n")
        self.log_text.see(tk.END)
        self.log_text.configure(state="disabled")

    def update_move_status(self) -> None:
        entered = len(self.moves_sequence)
        required = MINIMUM_MOVES if self.operation == "encrypt" else int(self.vault_metadata["move_count"])
        ready = entered >= required if self.operation == "encrypt" else entered == required
        over_limit = self.operation == "decrypt" and entered > required
        ratio = min(1.0, entered / max(1, required))

        if self.operation == "encrypt":
            self.move_count_var.set(f"{entered} moves entered  ·  minimum {required}")
        else:
            self.move_count_var.set(f"{entered} moves entered  ·  exactly {required} required")
        self.turn_var.set(f"Next turn: {'White' if self.current_turn else 'Black'}")
        self.progress_bar.set(ratio)

        if over_limit:
            self.ready_badge.configure(text="TOO MANY", fg_color=COLORS["danger_dark"], text_color=COLORS["danger"])
            self.progress_bar.configure(progress_color=COLORS["danger"])
            status = "Too many moves entered. Undo or reset before attempting decryption."
        elif ready:
            self.ready_badge.configure(text="READY", fg_color=COLORS["success_dark"], text_color=COLORS["success"])
            self.progress_bar.configure(progress_color=COLORS["success"])
            status = "Sequence requirement satisfied. The document action is now available."
        else:
            remaining = required - entered
            self.ready_badge.configure(text="BUILDING", fg_color=COLORS["warning_dark"], text_color=COLORS["warning"])
            self.progress_bar.configure(progress_color=COLORS["cyan"])
            status = f"Continue the sequence: {remaining} more valid move(s) required."

        try:
            sequence = sequence_identifier(self.moves_sequence) if entered >= MINIMUM_MOVES else None
        except (ValueError, MoveSequenceError):
            sequence = None
        self.sequence_preview_var.set(f"Sequence: {sequence or 'pending'}")
        self.status_var.set(status)

        self.undo_button.configure(state="normal" if entered else "disabled")
        if self.operation == "encrypt":
            self.encrypt_button.configure(state="normal" if ready else "disabled")
        else:
            state = "normal" if ready else "disabled"
            self.view_button.configure(state=state)
            self.download_button.configure(state=state)

    def reset_board(self) -> None:
        self.setup_board()
        self.selected_square = None
        self.hover_square = None
        self.last_move = None
        self.moves_sequence = []
        self.current_turn = True
        self.draw_board()
        self.render_move_timeline()
        self.update_move_status()
        self.log_move("Board reset. The entered sequence was cleared.")

    def undo_last_move(self) -> None:
        if not self.moves_sequence:
            self.log_move("There is no move to undo.")
            return
        retained_moves = [dict(move) for move in self.moves_sequence[:-1]]
        removed = self.moves_sequence[-1]
        self.setup_board()
        self.moves_sequence = []
        self.current_turn = True
        self.selected_square = None
        self.last_move = None

        for move in retained_moves:
            from_row, from_col = self.square_to_indices(move["from"])
            to_row, to_col = self.square_to_indices(move["to"])
            piece = self.board[from_row][from_col]
            if piece is None:
                raise RuntimeError("Unable to rebuild the board after undo.")
            self.board[to_row][to_col] = piece
            self.board[from_row][from_col] = None
            self.moves_sequence.append(move)
            self.current_turn = not self.current_turn
            self.last_move = ((from_row, from_col), (to_row, to_col))

        self.draw_board()
        self.render_move_timeline()
        self.update_move_status()
        self.log_move(f"Removed move: {removed['from']} → {removed['to']}")

    def update_clock(self) -> None:
        try:
            current_time = datetime.now(timezone.utc)
            self.time_label.configure(text=f"UTC {current_time.strftime('%Y-%m-%d  %H:%M:%S')}")
            self._clock_after_id = self.root.after(1000, self.update_clock)
        except tk.TclError:
            return

    # ------------------------------------------------------------------
    # Move TXT viewer
    # ------------------------------------------------------------------
    def open_move_text(self) -> None:
        path = filedialog.askopenfilename(
            parent=self.root,
            title="Open Sender's Move Instructions",
            filetypes=[("ChessVault move instructions", "*.txt"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            content = Path(path).read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            show_dialog(self.root, "Move TXT error", str(exc), kind="error")
            return

        viewer = ctk.CTkToplevel(self.root)
        viewer.title(f"Move Instructions — {Path(path).name}")
        viewer.configure(fg_color=COLORS["background"])
        viewer.transient(self.root)
        apply_window_icon(viewer)
        center_window(viewer, 720, 680, self.root)
        viewer.grid_columnconfigure(0, weight=1)
        viewer.grid_rowconfigure(1, weight=1)

        header = ctk.CTkFrame(viewer, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=24, pady=(22, 12))
        ctk.CTkLabel(header, text="Sender move instructions", text_color=COLORS["text"], font=font(22, "bold"), anchor="w").pack(anchor="w")
        ctk.CTkLabel(header, text=Path(path).name, text_color=COLORS["cyan"], font=mono_font(9, "bold"), anchor="w").pack(anchor="w", pady=(3, 0))

        text = ctk.CTkTextbox(
            viewer,
            wrap="word",
            fg_color=COLORS["surface"],
            border_width=1,
            border_color=COLORS["border"],
            corner_radius=16,
            text_color=COLORS["text_secondary"],
            font=mono_font(11),
        )
        text.grid(row=1, column=0, sticky="nsew", padx=24, pady=(0, 14))
        text.insert("1.0", content)
        text.configure(state="disabled")
        secondary_button(viewer, "Close instructions", viewer.destroy, width=180).grid(row=2, column=0, pady=(0, 22))
        viewer.grab_set()

    # ------------------------------------------------------------------
    # Encryption and decryption actions
    # ------------------------------------------------------------------
    def encrypt_document(self) -> VaultResult | None:
        self.encrypt_button.configure(text="Deriving key and encrypting…", state="disabled")
        self.status_var.set("Deriving the document key and building the authenticated vault…")
        self.root.update_idletasks()
        try:
            result = create_chessvault(
                source_path=self.selected_file,
                output_directory=self.output_directory,
                current_user=self.current_user,
                moves=self.moves_sequence,
            )
        except Exception as exc:
            self.log_move(f"Encryption failed: {exc}")
            self.encrypt_button.configure(text="Encrypt document + generate move TXT")
            self.update_move_status()
            show_dialog(self.root, "Encryption failed", str(exc), kind="error")
            return None

        self.log_move(f"Vault created: {result.vault_path}")
        self.log_move(f"Move TXT saved automatically: {result.moves_path}")
        self.encrypt_button.configure(text="Vault created successfully", state="disabled")
        show_dialog(
            self.root,
            "Encryption complete",
            "The encrypted vault and its ordered move instructions were created successfully.",
            kind="success",
            details=(
                f"Vault:\n{result.vault_path}\n\n"
                f"Move TXT:\n{result.moves_path}\n\n"
                f"Sequence ID: {result.sequence_id}"
            ),
        )
        if self.on_encrypted:
            self.on_encrypted(result)
        return result

    def _decrypt(self) -> tuple[dict, bytes] | None:
        self.status_var.set("Verifying the replayed sequence and document integrity…")
        self.view_button.configure(state="disabled")
        self.download_button.configure(state="disabled")
        self.root.update_idletasks()
        try:
            metadata, plaintext = decrypt_chessvault(self.selected_file, self.moves_sequence)
            self.log_move("Move sequence accepted. Document integrity verified.")
            return metadata, plaintext
        except (MoveSequenceError, VaultFormatError, ValueError, OSError) as exc:
            self.log_move(f"Decryption failed: {exc}")
            self.update_move_status()
            show_dialog(self.root, "Decryption failed", str(exc), kind="error")
            return None
        finally:
            if len(self.moves_sequence) == int(self.vault_metadata["move_count"]):
                self.view_button.configure(state="normal")
                self.download_button.configure(state="normal")

    def decrypt_and_view(self) -> Path | None:
        result = self._decrypt()
        if result is None:
            return None
        metadata, plaintext = result
        filename = Path(str(metadata["original_filename"])).name or "decrypted_document"

        temp_directory = Path(tempfile.mkdtemp(prefix="chessvault_view_"))
        self._temporary_view_directories.append(temp_directory)
        atexit.register(shutil.rmtree, temp_directory, True)
        output_path = temp_directory / filename
        output_path.write_bytes(plaintext)

        try:
            open_with_default_application(output_path)
        except Exception as exc:
            self.log_move(f"The document decrypted, but the system viewer could not open it: {exc}")
            show_dialog(
                self.root,
                "Viewer unavailable",
                "The document decrypted correctly, but the operating system could not launch a compatible viewer.",
                kind="warning",
                details=str(exc),
            )
            return output_path

        self.log_move(f"Opened decrypted document in the default application: {filename}")
        self.status_var.set(f"Document verified and opened: {filename}")
        return output_path

    def decrypt_and_download(self) -> Path | None:
        if self.vault_metadata is None:
            show_dialog(self.root, "Download error", "Vault metadata is unavailable.", kind="error")
            return None

        original_name = Path(str(self.vault_metadata["original_filename"])).name or "decrypted_document"
        original_suffix = Path(original_name).suffix
        save_path = filedialog.asksaveasfilename(
            parent=self.root,
            title="Save Decrypted Document As",
            initialfile=original_name,
            defaultextension=original_suffix,
            filetypes=[("Original document type", f"*{original_suffix}")] if original_suffix else [("All files", "*.*")],
        )
        if not save_path:
            return None

        result = self._decrypt()
        if result is None:
            return None
        _, plaintext = result

        destination = Path(save_path)
        temp_path = destination.with_name(f".{destination.name}.tmp-{os.getpid()}")
        try:
            destination.parent.mkdir(parents=True, exist_ok=True)
            temp_path.write_bytes(plaintext)
            os.replace(temp_path, destination)
        except OSError as exc:
            temp_path.unlink(missing_ok=True)
            show_dialog(self.root, "Download failed", str(exc), kind="error")
            return None

        self.log_move(f"Decrypted document downloaded to: {destination}")
        self.status_var.set(f"Document verified and downloaded: {destination.name}")
        show_dialog(
            self.root,
            "Download complete",
            "The original document was recovered and saved successfully.",
            kind="success",
            details=str(destination),
        )
        return destination

    def close_window(self) -> None:
        if self._clock_after_id:
            try:
                self.root.after_cancel(self._clock_after_id)
            except tk.TclError:
                pass
        self.root.destroy()


# Preserve the original import name used by main.py and older project code.
chess_encryption = ChessEncryptionWindow


if __name__ == "__main__":
    root = tk.Tk()
    root.withdraw()
    print("Run main.py to use the complete ChessVault application.")
    root.destroy()
