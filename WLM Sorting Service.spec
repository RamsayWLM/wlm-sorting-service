# -*- mode: python ; coding: utf-8 -*-

a = Analysis(
    ['client_shell.py'],
    pathex=[],
    binaries=[
        ('resources/ffmpeg', 'resources'),
    ],
    datas=[
        ('templates', 'templates'),
        ('static', 'static'),
        ('resources/exiftool', 'resources/exiftool'),
    ],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='WLM Sorting Service',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='WLM Sorting Service',
)
app = BUNDLE(
    coll,
    name='WLM Sorting Service.app',
    icon=None,
    bundle_identifier=None,
)
