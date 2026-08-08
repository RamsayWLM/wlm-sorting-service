#!/usr/bin/env python3
"""
WLM Local Thumbnail Generator
Generates thumbnails on this Mac using macOS native sips (fast, handles all RAW
formats, auto-applies EXIF rotation) and saves them to the NAS thumb directory.
The server picks them up instantly — no remote generation needed.

Usage:
  python3 generate_thumbs_local.py                        # cache everything
  python3 generate_thumbs_local.py "British Juniors 2026" # one folder
  python3 generate_thumbs_local.py --watch                 # keep running, pick up new files
"""

import os
import sys
import subprocess
import time
import threading
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

PHOTOS_BASE = Path('/Volumes/Public')
THUMB_BASE  = PHOTOS_BASE / '.wlm_thumbs'
THUMB_SIZE  = 480
WORKERS     = 8   # parallel workers — tune to taste

JPEG_EXTS  = {'.jpg', '.jpeg'}
RAW_EXTS   = {'.cr2', '.cr3', '.arw', '.nef', '.nrw', '.raf', '.rw2', '.orf', '.dng', '.pef', '.srw', '.x3f'}
VIDEO_EXTS = {'.mov', '.mp4', '.mts', '.m2ts', '.mkv', '.avi'}
MEDIA_EXTS = JPEG_EXTS | RAW_EXTS | VIDEO_EXTS


def thumb_path(src: Path) -> Path:
    rel = src.relative_to(PHOTOS_BASE)
    return THUMB_BASE / (str(rel) + '.jpg')


def make_thumb(src: Path, dst: Path) -> bool:
    dst.parent.mkdir(parents=True, exist_ok=True)
    ext = src.suffix.lower()
    try:
        if ext in VIDEO_EXTS:
            r = subprocess.run(
                ['ffmpeg', '-y', '-ss', '2', '-i', str(src),
                 '-vframes', '1', '-vf', f'scale={THUMB_SIZE}:-2', '-q:v', '5', str(dst)],
                capture_output=True, timeout=60
            )
        else:
            # sips: macOS native, handles JPEG + all RAW formats
            r = subprocess.run(
                ['sips', '-s', 'format', 'jpeg', '-Z', str(THUMB_SIZE), str(src), '--out', str(dst)],
                capture_output=True, timeout=30
            )
            # sips preserves the EXIF orientation tag but doesn't physically rotate pixels.
            # Apply exif_transpose to bake rotation into pixels so browsers display correctly.
            if dst.exists() and dst.stat().st_size > 500:
                try:
                    from PIL import Image, ImageOps
                    with Image.open(str(dst)) as img:
                        rotated = ImageOps.exif_transpose(img)
                        if rotated is not img:
                            rotated.save(str(dst), 'JPEG', quality=82, optimize=True)
                except Exception:
                    pass
        return dst.exists() and dst.stat().st_size > 500
    except Exception:
        return False


def collect_files(folder: Path) -> list[Path]:
    files = []
    for root, dirs, filenames in os.walk(str(folder)):
        dirs[:] = sorted(d for d in dirs if not d.startswith('.'))
        rp = Path(root)
        for f in sorted(filenames):
            if not f.startswith('.') and Path(f).suffix.lower() in MEDIA_EXTS:
                files.append(rp / f)
    return files


def generate(folder: Path, watch: bool = False):
    if not PHOTOS_BASE.exists():
        print(f"Error: {PHOTOS_BASE} not mounted. Connect to the NAS first.")
        sys.exit(1)

    THUMB_BASE.mkdir(parents=True, exist_ok=True)

    while True:
        files = collect_files(folder)
        pending = [f for f in files if not (lambda d: d.exists() and d.stat().st_mtime >= f.stat().st_mtime)(thumb_path(f))]

        if not pending:
            if watch:
                print(f"\r✓ All {len(files)} files cached. Watching for new files…  ", end='', flush=True)
                time.sleep(30)
                continue
            else:
                print(f"✓ All {len(files)} files already cached.")
                return

        total   = len(pending)
        done    = 0
        errors  = 0
        skipped = len(files) - len(pending)
        lock    = threading.Lock()
        start   = time.time()

        label = folder.name
        print(f"Generating {total} thumbnails for '{label}'"
              + (f" ({skipped} already cached)" if skipped else "") + f" — {WORKERS} workers")

        def _process(fp):
            nonlocal done, errors
            dst = thumb_path(fp)
            ok  = make_thumb(fp, dst)
            with lock:
                done += 1
                if not ok:
                    errors += 1
                _print_progress(done, total, errors, start)

        with ThreadPoolExecutor(max_workers=WORKERS) as pool:
            pool.map(_process, pending)

        elapsed = time.time() - start
        rate    = (total - errors) / elapsed if elapsed else 0
        print(f"\n✓ Done in {elapsed:.1f}s  ({rate:.1f}/s)  —  "
              f"{total - errors} generated, {skipped} skipped, {errors} errors")

        if not watch:
            break

        print("Watching for new files… (Ctrl+C to stop)")
        time.sleep(30)


def _print_progress(done, total, errors, start):
    pct     = done / total * 100
    filled  = int(pct / 2)
    bar     = '█' * filled + '░' * (50 - filled)
    elapsed = time.time() - start
    eta     = ''
    if done > 0 and elapsed > 0:
        remaining = int((total - done) * elapsed / done)
        eta = f"  ETA {remaining // 60}m{remaining % 60:02d}s" if remaining >= 60 else f"  ETA {remaining}s"
    err_str = f"  {errors} errors" if errors else ''
    print(f"\r[{bar}] {done}/{total} ({pct:.0f}%){eta}{err_str}  ", end='', flush=True)


if __name__ == '__main__':
    args   = [a for a in sys.argv[1:] if not a.startswith('--')]
    watch  = '--watch' in sys.argv

    if args:
        target = PHOTOS_BASE / args[0]
        if not target.is_dir():
            print(f"Error: '{target}' is not a directory")
            sys.exit(1)
    else:
        target = PHOTOS_BASE

    try:
        generate(target, watch=watch)
    except KeyboardInterrupt:
        print("\nStopped.")
