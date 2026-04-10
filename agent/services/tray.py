from __future__ import annotations

import ctypes
import logging
import sys
import threading
import webbrowser
from dataclasses import dataclass
from pathlib import Path
from ctypes import wintypes


LOGGER = logging.getLogger(__name__)

if sys.platform == "win32":
    if ctypes.sizeof(ctypes.c_void_p) == 8:
        WPARAM_T = ctypes.c_uint64
        LPARAM_T = ctypes.c_int64
        LRESULT_T = ctypes.c_ssize_t
    else:  # pragma: no cover - 32-bit Windows
        WPARAM_T = ctypes.c_uint32
        LPARAM_T = ctypes.c_int32
        LRESULT_T = ctypes.c_long

    user32 = ctypes.windll.user32
    shell32 = ctypes.windll.shell32
    gdi32 = ctypes.windll.gdi32
    user32.DefWindowProcW.argtypes = [wintypes.HWND, wintypes.UINT, WPARAM_T, LPARAM_T]
    user32.DefWindowProcW.restype = LRESULT_T
    user32.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, WPARAM_T, LPARAM_T]
    user32.PostMessageW.restype = wintypes.BOOL
    user32.GetMessageW.argtypes = [ctypes.POINTER(wintypes.MSG), wintypes.HWND, wintypes.UINT, wintypes.UINT]
    user32.GetMessageW.restype = wintypes.BOOL
    user32.TranslateMessage.argtypes = [ctypes.POINTER(wintypes.MSG)]
    user32.TranslateMessage.restype = wintypes.BOOL
    user32.DispatchMessageW.argtypes = [ctypes.POINTER(wintypes.MSG)]
    user32.DispatchMessageW.restype = LRESULT_T
else:  # pragma: no cover - tray is Windows-only
    user32 = None
    shell32 = None
    gdi32 = None


WM_DESTROY = 0x0002
WM_CLOSE = 0x0010
WM_COMMAND = 0x0111
WM_USER = 0x0400
WM_RBUTTONUP = 0x0205
WM_LBUTTONDBLCLK = 0x0203
WM_LBUTTONUP = 0x0202
NIM_ADD = 0x00000000
NIM_MODIFY = 0x00000001
NIM_DELETE = 0x00000002
NIF_MESSAGE = 0x00000001
NIF_ICON = 0x00000002
NIF_TIP = 0x00000004
MF_STRING = 0x00000000
TPM_RIGHTBUTTON = 0x0002
IDI_APPLICATION = 32512
LR_DEFAULTSIZE = 0x0040
LR_SHARED = 0x8000
IMAGE_ICON = 1
SW_HIDE = 0
SW_SHOWNORMAL = 1
ID_SHOW = 1001
ID_CLOSE = 1002


class NOTIFYICONDATAW(ctypes.Structure):
    _fields_ = [
        ("cbSize", ctypes.c_ulong),
        ("hWnd", ctypes.c_void_p),
        ("uID", ctypes.c_uint),
        ("uFlags", ctypes.c_uint),
        ("uCallbackMessage", ctypes.c_uint),
        ("hIcon", ctypes.c_void_p),
        ("szTip", ctypes.c_wchar * 128),
        ("dwState", ctypes.c_uint),
        ("dwStateMask", ctypes.c_uint),
        ("szInfo", ctypes.c_wchar * 256),
        ("uTimeoutOrVersion", ctypes.c_uint),
        ("szInfoTitle", ctypes.c_wchar * 64),
        ("dwInfoFlags", ctypes.c_uint),
        ("guidItem", ctypes.c_byte * 16),
        ("hBalloonIcon", ctypes.c_void_p),
    ]


class POINT(ctypes.Structure):
    _fields_ = [("x", ctypes.c_long), ("y", ctypes.c_long)]


@dataclass
class TrayController:
    url: str
    stop_event: threading.Event | None = None

    def __post_init__(self) -> None:
        self._closed = False
        self._hwnd: int | None = None
        self._hicon: int | None = None
        self._class_atom: int | None = None
        self._wndproc = None
        self._taskbar_created = user32.RegisterWindowMessageW("TaskbarCreated") if user32 else 0

    def _show(self) -> None:
        target = self.url.strip()
        if not target:
            LOGGER.warning("Tray show requested but URL is empty")
            return
        LOGGER.info("Tray show requested: %s", target)
        webbrowser.open_new_tab(target)

    def _close(self) -> None:
        if self._closed:
            return
        self._closed = True
        LOGGER.info("Tray close requested")
        if self.stop_event is not None:
            self.stop_event.set()
        if self._hwnd and user32:
            user32.PostMessageW(self._hwnd, WM_CLOSE, 0, 0)

    def _load_icon(self) -> int:
        if not user32:
            return 0
        exe_path = str(Path(sys.executable).resolve())
        icon = shell32.ExtractIconW(None, exe_path, 0)
        if icon:
            return icon
        return 0

    def _add_tray_icon(self) -> None:
        if not user32 or not self._hwnd:
            return
        self._hicon = self._load_icon()
        data = NOTIFYICONDATAW()
        data.cbSize = ctypes.sizeof(NOTIFYICONDATAW)
        data.hWnd = self._hwnd
        data.uID = 1
        data.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP
        data.uCallbackMessage = WM_USER + 20
        data.hIcon = self._hicon or 0
        data.szTip = "GoPrinxAgent"
        shell32.Shell_NotifyIconW(NIM_ADD, ctypes.byref(data))
        shell32.Shell_NotifyIconW(NIM_MODIFY, ctypes.byref(data))

    def _remove_tray_icon(self) -> None:
        if not user32 or not self._hwnd:
            return
        data = NOTIFYICONDATAW()
        data.cbSize = ctypes.sizeof(NOTIFYICONDATAW)
        data.hWnd = self._hwnd
        data.uID = 1
        shell32.Shell_NotifyIconW(NIM_DELETE, ctypes.byref(data))

    def _show_menu(self) -> None:
        if not user32 or not self._hwnd:
            return
        menu = user32.CreatePopupMenu()
        if not menu:
            return
        try:
            user32.AppendMenuW(menu, MF_STRING, ID_SHOW, "Show")
            user32.AppendMenuW(menu, MF_STRING, ID_CLOSE, "Close")
            user32.SetForegroundWindow(self._hwnd)
            pt = POINT()
            user32.GetCursorPos(ctypes.byref(pt))
            user32.TrackPopupMenu(menu, TPM_RIGHTBUTTON, pt.x, pt.y, 0, self._hwnd, None)
            user32.PostMessageW(self._hwnd, WM_USER + 21, 0, 0)
        finally:
            user32.DestroyMenu(menu)

    def _create_window(self) -> int:
        if not user32:
            return 0

        hinstance = ctypes.windll.kernel32.GetModuleHandleW(None)
        class_name = f"GoPrinxAgentTray_{id(self):x}"

        WNDPROCTYPE = ctypes.WINFUNCTYPE(LRESULT_T, wintypes.HWND, wintypes.UINT, WPARAM_T, LPARAM_T)

        def wndproc(hwnd, msg, wparam, lparam):
            if msg == self._taskbar_created:
                self._add_tray_icon()
                return 0
            if msg == WM_COMMAND:
                command = int(wparam) & 0xFFFF
                if command == ID_SHOW:
                    self._show()
                elif command == ID_CLOSE:
                    self._close()
                return 0
            if msg == WM_USER + 20:
                if lparam in (WM_LBUTTONDBLCLK, WM_LBUTTONUP):
                    self._show()
                elif lparam == WM_RBUTTONUP:
                    self._show_menu()
                return 0
            if msg == WM_CLOSE:
                self._remove_tray_icon()
                user32.DestroyWindow(hwnd)
                return 0
            if msg == WM_DESTROY:
                self._remove_tray_icon()
                user32.PostQuitMessage(0)
                return 0
            return user32.DefWindowProcW(hwnd, msg, wparam, lparam)

        self._wndproc = WNDPROCTYPE(wndproc)

        class WNDCLASS(ctypes.Structure):
            _fields_ = [
                ("style", ctypes.c_uint),
                ("lpfnWndProc", WNDPROCTYPE),
                ("cbClsExtra", ctypes.c_int),
                ("cbWndExtra", ctypes.c_int),
                ("hInstance", ctypes.c_void_p),
                ("hIcon", ctypes.c_void_p),
                ("hCursor", ctypes.c_void_p),
                ("hbrBackground", ctypes.c_void_p),
                ("lpszMenuName", ctypes.c_wchar_p),
                ("lpszClassName", ctypes.c_wchar_p),
            ]

        wc = WNDCLASS()
        wc.style = 0
        wc.lpfnWndProc = self._wndproc
        wc.cbClsExtra = 0
        wc.cbWndExtra = 0
        wc.hInstance = hinstance
        wc.hIcon = self._load_icon()
        wc.hCursor = 0
        wc.hbrBackground = 0
        wc.lpszMenuName = None
        wc.lpszClassName = class_name

        self._class_atom = user32.RegisterClassW(ctypes.byref(wc))
        hwnd = user32.CreateWindowExW(
            0,
            class_name,
            "GoPrinxAgentTray",
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            hinstance,
            None,
        )
        self._hwnd = hwnd
        return hwnd

    def run(self) -> None:
        if sys.platform != "win32":
            LOGGER.info("Tray icon is Windows-only; skipping tray")
            return
        LOGGER.info("Tray icon starting")
        hwnd = self._create_window()
        if not hwnd:
            LOGGER.warning("Failed to create tray window")
            return
        self._add_tray_icon()
        user32.ShowWindow(hwnd, SW_HIDE)
        user32.UpdateWindow(hwnd)

        msg = wintypes.MSG()
        while not self._closed:
            ret = user32.GetMessageW(ctypes.byref(msg), 0, 0, 0)
            if ret == 0:
                break
            if ret == -1:
                LOGGER.warning("Tray message loop error")
                break
            user32.TranslateMessage(ctypes.byref(msg))
            user32.DispatchMessageW(ctypes.byref(msg))

        self._remove_tray_icon()
        try:
            if self._hwnd:
                user32.DestroyWindow(self._hwnd)
        except Exception:
            pass
        LOGGER.info("Tray icon stopped")
