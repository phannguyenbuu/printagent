# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_submodules

hiddenimports = ['agent.services.tray']
hiddenimports += collect_submodules('agent.modules')
hiddenimports += collect_submodules('agent.services')
hiddenimports += collect_submodules('agent.utils')


a = Analysis(
    ['agent\\main.py'],
    pathex=['.'],
    binaries=[],
    datas=[('agent/templates', 'agent/templates')],
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['torch', 'torchvision', 'torchaudio', 'sklearn', 'scipy', 'matplotlib', 'numba', 'llvmlite', 'pandas', 'cv2', 'PIL', 'imageio_ffmpeg', 'IPython', 'jupyter', 'notebook', 'traitlets'],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='printagent',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['agent\\icon.ico'],
)
