from __future__ import annotations

import os
import tkinter as tk
from datetime import datetime
from pathlib import Path
from typing import Callable

import customtkinter as ctk
from PIL import Image, ImageDraw


# ChessVault visual system: deep navy surfaces, cold cyan security accents,
# and restrained gold for chess-specific emphasis.
COLORS = {
    "void": "#05070D",
    "background": "#080C16",
    "background_2": "#0C1220",
    "sidebar": "#090E19",
    "surface": "#101827",
    "surface_2": "#151F31",
    "surface_3": "#1A263A",
    "surface_hover": "#1D2B42",
    "border": "#24334A",
    "border_soft": "#1A273A",
    "text": "#F3F7FC",
    "text_secondary": "#A7B4C7",
    "text_muted": "#6F8098",
    "cyan": "#38D6D0",
    "cyan_hover": "#55E7E1",
    "cyan_dark": "#123C42",
    "blue": "#5B8CFF",
    "blue_dark": "#152C5A",
    "gold": "#E6B85C",
    "gold_hover": "#F2C871",
    "gold_dark": "#49391D",
    "success": "#43D19E",
    "success_dark": "#123C31",
    "warning": "#F3B45E",
    "warning_dark": "#473018",
    "danger": "#FF6B7A",
    "danger_hover": "#FF8490",
    "danger_dark": "#461D28",
    "white_square": "#DDE6EC",
    "black_square": "#50657C",
    "white_square_hover": "#E7EFF4",
    "black_square_hover": "#5E748C",
    "selection": "#E8BD61",
    "last_move": "#75A6D6",
    "legal_move": "#2D655F",
}

ASSET_DIRECTORY = Path(__file__).resolve().parent / "assets"
ICON_PATH = ASSET_DIRECTORY / "chessvault_icon.png"


def configure_customtkinter() -> None:
    ctk.set_appearance_mode("dark")
    # A built-in theme is still required by CustomTkinter internally; all visible
    # widget colours are explicitly controlled by this module.
    ctk.set_default_color_theme("blue")


def font(size: int, weight: str = "normal", family: str = "Segoe UI") -> ctk.CTkFont:
    return ctk.CTkFont(family=family, size=size, weight=weight)


def mono_font(size: int, weight: str = "normal") -> ctk.CTkFont:
    return ctk.CTkFont(family="Consolas", size=size, weight=weight)


def center_window(window: tk.Misc, width: int, height: int, parent: tk.Misc | None = None) -> None:
    window.update_idletasks()
    if parent is not None and parent.winfo_exists():
        parent.update_idletasks()
        x = parent.winfo_rootx() + max(0, (parent.winfo_width() - width) // 2)
        y = parent.winfo_rooty() + max(0, (parent.winfo_height() - height) // 2)
    else:
        x = max(0, (window.winfo_screenwidth() - width) // 2)
        y = max(0, (window.winfo_screenheight() - height) // 2)
    window.geometry(f"{width}x{height}+{x}+{y}")


def format_bytes(size: int) -> str:
    value = float(size)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024.0 or unit == "TB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024.0
    return f"{size} B"


def format_timestamp(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp).strftime("%d %b %Y · %H:%M")


def ensure_icon_asset() -> Path:
    """Create the geometric application icon when the asset is absent."""
    if ICON_PATH.exists():
        return ICON_PATH

    ASSET_DIRECTORY.mkdir(parents=True, exist_ok=True)
    size = 512
    image = Image.new("RGBA", (size, size), COLORS["background"])
    draw = ImageDraw.Draw(image)

    # Layered shield.
    shield = [(256, 38), (430, 106), (400, 346), (256, 468), (112, 346), (82, 106)]
    draw.polygon(shield, fill="#0F1A2B", outline=COLORS["cyan"], width=18)
    inner = [(256, 78), (390, 130), (368, 322), (256, 420), (144, 322), (122, 130)]
    draw.polygon(inner, fill="#111F31", outline="#24445B", width=8)

    # Stylised rook / vault keyhole mark.
    gold = COLORS["gold"]
    draw.rounded_rectangle((178, 180, 334, 345), radius=22, fill=gold)
    draw.rectangle((160, 145, 352, 215), fill=gold)
    for x in (170, 236, 302):
        draw.rectangle((x, 118, x + 40, 170), fill=gold)
    draw.ellipse((232, 236, 280, 284), fill=COLORS["background"])
    draw.polygon([(250, 272), (262, 272), (278, 324), (234, 324)], fill=COLORS["background"])

    image.save(ICON_PATH)
    return ICON_PATH


def apply_window_icon(window: tk.Misc) -> None:
    try:
        icon_path = ensure_icon_asset()
        icon = tk.PhotoImage(file=str(icon_path))
        window.iconphoto(True, icon)
        setattr(window, "_chessvault_window_icon", icon)
    except (tk.TclError, OSError):
        pass


def logo_image(size: int = 54) -> ctk.CTkImage:
    path = ensure_icon_asset()
    image = Image.open(path).convert("RGBA")
    return ctk.CTkImage(light_image=image, dark_image=image, size=(size, size))


class GradientCanvas(tk.Canvas):
    """A lightweight, resize-aware vertical gradient for page backgrounds."""

    def __init__(self, master: tk.Misc, start: str, end: str, **kwargs):
        super().__init__(master, highlightthickness=0, bd=0, **kwargs)
        self.start = start
        self.end = end
        self.bind("<Configure>", self._draw_gradient)

    @staticmethod
    def _rgb(widget: tk.Misc, colour: str) -> tuple[int, int, int]:
        r, g, b = widget.winfo_rgb(colour)
        return r // 256, g // 256, b // 256

    def _draw_gradient(self, _event: tk.Event | None = None) -> None:
        self.delete("gradient")
        width = max(1, self.winfo_width())
        height = max(1, self.winfo_height())
        r1, g1, b1 = self._rgb(self, self.start)
        r2, g2, b2 = self._rgb(self, self.end)
        steps = min(height, 180)
        band = max(1, height // steps + 1)
        for index in range(steps):
            ratio = index / max(1, steps - 1)
            r = int(r1 + (r2 - r1) * ratio)
            g = int(g1 + (g2 - g1) * ratio)
            b = int(b1 + (b2 - b1) * ratio)
            colour = f"#{r:02x}{g:02x}{b:02x}"
            y1 = index * height / steps
            y2 = y1 + band
            self.create_rectangle(0, y1, width, y2, fill=colour, outline=colour, tags="gradient")
        self.lower("gradient")


class PremiumDialog:
    """Modal ChessVault dialog used instead of native message boxes."""

    def __init__(
        self,
        parent: tk.Misc,
        title: str,
        message: str,
        *,
        kind: str = "info",
        details: str | None = None,
        confirm: bool = False,
        confirm_text: str = "Continue",
        cancel_text: str = "Cancel",
    ) -> None:
        self.result = False
        self.window = ctk.CTkToplevel(parent)
        self.window.title(title)
        self.window.configure(fg_color=COLORS["background"])
        self.window.resizable(False, False)
        self.window.transient(parent)
        apply_window_icon(self.window)

        palette = {
            "info": (COLORS["cyan"], COLORS["cyan_dark"], "i"),
            "success": (COLORS["success"], COLORS["success_dark"], "✓"),
            "warning": (COLORS["warning"], COLORS["warning_dark"], "!"),
            "error": (COLORS["danger"], COLORS["danger_dark"], "×"),
        }
        accent, accent_dark, symbol = palette.get(kind, palette["info"])

        shell = ctk.CTkFrame(
            self.window,
            fg_color=COLORS["surface"],
            corner_radius=22,
            border_width=1,
            border_color=COLORS["border"],
        )
        shell.pack(fill="both", expand=True, padx=18, pady=18)

        header = ctk.CTkFrame(shell, fg_color="transparent")
        header.pack(fill="x", padx=24, pady=(24, 10))
        icon = ctk.CTkLabel(
            header,
            text=symbol,
            width=44,
            height=44,
            corner_radius=22,
            fg_color=accent_dark,
            text_color=accent,
            font=font(24, "bold"),
        )
        icon.pack(side="left", padx=(0, 14))
        ctk.CTkLabel(
            header,
            text=title,
            text_color=COLORS["text"],
            font=font(19, "bold"),
            anchor="w",
        ).pack(side="left", fill="x", expand=True)

        ctk.CTkLabel(
            shell,
            text=message,
            text_color=COLORS["text_secondary"],
            font=font(13),
            justify="left",
            anchor="w",
            wraplength=470,
        ).pack(fill="x", padx=26, pady=(4, 12))

        if details:
            detail_box = ctk.CTkTextbox(
                shell,
                height=90,
                fg_color=COLORS["background_2"],
                border_width=1,
                border_color=COLORS["border_soft"],
                corner_radius=12,
                text_color=COLORS["text_secondary"],
                font=mono_font(11),
                wrap="word",
            )
            detail_box.pack(fill="x", padx=26, pady=(0, 14))
            detail_box.insert("1.0", details)
            detail_box.configure(state="disabled")

        buttons = ctk.CTkFrame(shell, fg_color="transparent")
        buttons.pack(fill="x", padx=24, pady=(8, 24))
        if confirm:
            ctk.CTkButton(
                buttons,
                text=cancel_text,
                command=self._cancel,
                height=40,
                corner_radius=12,
                fg_color=COLORS["surface_2"],
                hover_color=COLORS["surface_hover"],
                border_width=1,
                border_color=COLORS["border"],
                text_color=COLORS["text_secondary"],
                font=font(12, "bold"),
            ).pack(side="right", padx=(8, 0))

        ctk.CTkButton(
            buttons,
            text=confirm_text if confirm else "Close",
            command=self._confirm,
            height=40,
            corner_radius=12,
            fg_color=accent,
            hover_color=COLORS["cyan_hover"] if kind == "info" else accent,
            text_color=COLORS["void"],
            font=font(12, "bold"),
        ).pack(side="right")

        self.window.protocol("WM_DELETE_WINDOW", self._cancel if confirm else self._confirm)
        center_window(self.window, 560, 330 if details else 260, parent)
        self.window.grab_set()
        self.window.focus_force()
        self.window.wait_window()

    def _confirm(self) -> None:
        self.result = True
        self.window.destroy()

    def _cancel(self) -> None:
        self.result = False
        self.window.destroy()


def show_dialog(
    parent: tk.Misc,
    title: str,
    message: str,
    *,
    kind: str = "info",
    details: str | None = None,
    confirm: bool = False,
    confirm_text: str = "Continue",
    cancel_text: str = "Cancel",
) -> bool:
    dialog = PremiumDialog(
        parent,
        title,
        message,
        kind=kind,
        details=details,
        confirm=confirm,
        confirm_text=confirm_text,
        cancel_text=cancel_text,
    )
    return dialog.result


def primary_button(parent: tk.Misc, text: str, command: Callable[[], None], **kwargs) -> ctk.CTkButton:
    return ctk.CTkButton(
        parent,
        text=text,
        command=command,
        height=44,
        corner_radius=12,
        fg_color=COLORS["cyan"],
        hover_color=COLORS["cyan_hover"],
        text_color=COLORS["void"],
        font=font(12, "bold"),
        **kwargs,
    )


def secondary_button(parent: tk.Misc, text: str, command: Callable[[], None], **kwargs) -> ctk.CTkButton:
    return ctk.CTkButton(
        parent,
        text=text,
        command=command,
        height=42,
        corner_radius=12,
        fg_color=COLORS["surface_2"],
        hover_color=COLORS["surface_hover"],
        border_width=1,
        border_color=COLORS["border"],
        text_color=COLORS["text"],
        font=font(12, "bold"),
        **kwargs,
    )


def danger_button(parent: tk.Misc, text: str, command: Callable[[], None], **kwargs) -> ctk.CTkButton:
    return ctk.CTkButton(
        parent,
        text=text,
        command=command,
        height=42,
        corner_radius=12,
        fg_color=COLORS["danger_dark"],
        hover_color=COLORS["danger"],
        border_width=1,
        border_color="#6E2B39",
        text_color=COLORS["danger"],
        font=font(12, "bold"),
        **kwargs,
    )
