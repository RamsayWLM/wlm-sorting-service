#!/usr/bin/env python3
import hmac
import io
import json
import os
import queue
import re
import shutil
import subprocess
import threading
import time
import uuid
import zipfile

import psutil
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from io import BytesIO
from pathlib import Path

from flask import (
    Flask, jsonify, send_file, render_template, render_template_string,
    abort, request, redirect, session, url_for, Response,
)

try:
    from PIL import Image, ImageOps
    HAS_PILLOW = True
    _EXIF_ORIENT_OPS = {
        2: Image.FLIP_LEFT_RIGHT,
        3: Image.ROTATE_180,
        4: Image.FLIP_TOP_BOTTOM,
        5: Image.TRANSPOSE,
        6: Image.ROTATE_270,
        7: Image.TRANSVERSE,
        8: Image.ROTATE_90,
    }
except ImportError:
    HAS_PILLOW = False
    _EXIF_ORIENT_OPS = {}

app = Flask(__name__)
app.config['TEMPLATES_AUTO_RELOAD'] = True

# ── Auth ──────────────────────────────────────────────────────────────────────

WLM_PASSWORD = os.environ.get('WLM_PASSWORD', 'Yellowmango1!')
_SECRET_KEY_FILE = Path(os.environ.get('PHOTOS_DIR', '/photos')) / '.wlm_secret_key'

def _load_secret_key() -> str:
    """Persist the Flask session secret on disk so logins survive container restarts."""
    try:
        if _SECRET_KEY_FILE.is_file():
            return _SECRET_KEY_FILE.read_text().strip()
    except Exception:
        pass
    key = uuid.uuid4().hex + uuid.uuid4().hex
    try:
        _SECRET_KEY_FILE.write_text(key)
    except Exception:
        pass
    return key

app.secret_key = _load_secret_key()
app.permanent_session_lifetime = timedelta(days=30)

_LOGIN_PAGE = """
<!doctype html><html><head><meta name="viewport" content="width=device-width, initial-scale=1">
<title>WLM Photo Viewer — Login</title>
<style>
  html, body { height: 100%; margin: 0; display: flex; align-items: center; justify-content: center;
    background: #181818; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; }
  form { background: #242424; border: 1px solid #333; border-radius: 10px; padding: 32px;
    width: 260px; text-align: center; }
  .logo-dot { width: 28px; height: 28px; border-radius: 50%; background: #d4a017; margin: 0 auto 14px; }
  h1 { font-size: 14px; color: #e0e0e0; margin: 0 0 18px; font-weight: 600; }
  input { width: 100%; box-sizing: border-box; background: #1c1c1c; border: 1px solid #333;
    border-radius: 6px; color: #e0e0e0; padding: 10px 12px; font-size: 14px; margin-bottom: 12px; }
  input:focus { outline: none; border-color: #d4a017; }
  button { width: 100%; background: #d4a017; border: none; border-radius: 6px; color: #181818;
    font-weight: 700; padding: 10px; font-size: 14px; cursor: pointer; }
  button:hover { background: #e0ac1c; }
  label { display: flex; align-items: center; gap: 6px; color: #707070; font-size: 12px;
    margin-bottom: 14px; justify-content: center; }
  .error { color: #e84a4a; font-size: 12px; margin-bottom: 12px; }
</style></head>
<body>
<form method="post">
  <div class="logo-dot"></div>
  <h1>WLM Photo Viewer</h1>
  {% if error %}<div class="error">{{ error }}</div>{% endif %}
  <input id="pw" type="password" name="password" placeholder="Password" autofocus required>
  <label><input type="checkbox" onchange="pw.type = this.checked ? 'text' : 'password';" style="width:auto;margin:0;"> Show password</label>
  <label><input type="checkbox" name="remember" value="1" checked style="width:auto;margin:0;"> Stay signed in</label>
  <button type="submit">Sign in</button>
</form>
</body></html>
"""

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        password = request.form.get('password', '')
        if hmac.compare_digest(password, WLM_PASSWORD):
            session.clear()
            session['authed'] = True
            session.permanent = bool(request.form.get('remember'))
            return redirect(url_for('index'))
        return render_template_string(_LOGIN_PAGE, error='Incorrect password'), 401
    return render_template_string(_LOGIN_PAGE, error=None)


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.before_request
def _require_login():
    if request.endpoint in ('login', 'logout', 'static', 'api_matcher_heartbeat',
                            'api_matcher_photos_in', 'api_matcher_thumb',
                            'api_matcher_next_job', 'api_matcher_job_update'):
        return
    if not session.get('authed'):
        return redirect(url_for('login'))

# ── AI Sort Assistant: matcher auto-discovery ───────────────────────────────
# The matching engine (PowerNet) needs a GPU the NAS doesn't have, so it runs on
# whichever Mac (Ramsay's laptop, the venue Mac mini, ...) is available and
# announces itself here over Tailscale every ~15s. No IP/hostname to configure —
# whoever's machine is running matcher_service.py right now is the one we use.
# Heartbeats older than MATCHER_TTL are dropped, so a closed laptop or sleeping
# Mac mini just falls out of the list on its own.
MATCHER_KEY = os.environ.get('MATCHER_KEY', WLM_PASSWORD)
MATCHER_TTL = 45  # seconds

_matchers = {}       # machine_id -> {hostname, ip, port, gpu, last_seen}
_matchers_mu = threading.Lock()


@app.route('/api/matcher/heartbeat', methods=['POST'])
def api_matcher_heartbeat():
    if not hmac.compare_digest(request.headers.get('X-Matcher-Key', ''), MATCHER_KEY):
        abort(403)
    data = request.get_json(force=True, silent=True) or {}
    # Prefer the matcher's self-reported Tailscale IP: some NAS Docker setups NAT
    # inbound traffic behind a bridge gateway, so request.remote_addr can be a
    # docker0-style address instead of the real caller. Only trust a value that
    # actually looks like a Tailscale IP (100.64.0.0/10 CGNAT range).
    reported_ip = str(data.get('tailscale_ip', ''))[:45]
    ip = reported_ip if re.match(r'^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d{1,3}\.\d{1,3}$', reported_ip) \
        else request.remote_addr
    hostname = str(data.get('hostname', ip))[:80]
    machine_id = f"{hostname}@{ip}"
    with _matchers_mu:
        _matchers[machine_id] = {
            'machine_id': machine_id,
            'hostname': hostname,
            'ip': ip,
            'port': int(data.get('port', 8770)),
            'gpu': str(data.get('gpu', ''))[:20],
            'last_seen': time.time(),
        }
    return jsonify({'ok': True})


def _online_matchers():
    now = time.time()
    with _matchers_mu:
        stale = [k for k, m in _matchers.items() if now - m['last_seen'] >= MATCHER_TTL]
        for k in stale:
            del _matchers[k]
        return sorted(_matchers.values(), key=lambda m: -m['last_seen'])


@app.route('/api/matcher/status')
def api_matcher_status():
    online = _online_matchers()
    return jsonify({'matchers': online, 'active': online[0] if online else None})

def _nat(s: str):
    """Natural sort key: splits '10.Name' so 2 < 10 numerically."""
    return [int(c) if c.isdigit() else c.lower() for c in re.split(r'(\d+)', s)]

BASE              = Path(os.environ.get('PHOTOS_DIR', '/photos'))
TRASH_DIR         = BASE / '.wlm_trash'
THUMB_DIR         = Path(os.environ.get('THUMB_DIR', '/tmp/wlm_thumbs'))
THUMB_SIZE        = 480
THUMB_QUALITY     = 82
# "Extra small cache" mode -- for remote viewers on slow uplinks (bandwidth, not
# generation speed, is the actual bottleneck there; see the size/quality tradeoff
# measured empirically before picking these numbers).
THUMB_SIZE_SMALL    = 280
THUMB_QUALITY_SMALL = 65
CACHE_EXPIRY_DAYS = 7
CACHE_META_FILE   = THUMB_DIR / '.cache_meta.json'
THUMB_CONFIG_FILE  = THUMB_DIR / '.thumb_config.json'

def _load_small_cache_pref() -> bool:
    try:
        return bool(json.loads(THUMB_CONFIG_FILE.read_text()).get('small_cache', False))
    except (OSError, ValueError):
        return False

_small_cache_enabled = _load_small_cache_pref()

def _cur_thumb_size() -> int:
    return THUMB_SIZE_SMALL if _small_cache_enabled else THUMB_SIZE

def _cur_thumb_quality() -> int:
    return THUMB_QUALITY_SMALL if _small_cache_enabled else THUMB_QUALITY

JPEG_EXTS  = {'.jpg', '.jpeg'}
RAW_EXTS   = {'.cr2', '.cr3', '.arw', '.nef', '.nrw', '.raf', '.rw2', '.orf', '.dng', '.pef', '.srw', '.x3f'}
VIDEO_EXTS = {'.mov', '.mp4', '.mts', '.m2ts', '.mkv', '.avi'}
PHOTO_EXTS = JPEG_EXTS | RAW_EXTS
MEDIA_EXTS = PHOTO_EXTS | VIDEO_EXTS

LOGO_PATH = Path(__file__).parent / 'static' / 'wlm_logo.png'

# -- AI Sort Assistant: proxy to whichever matcher machine is currently online --

def _active_matcher():
    online = _online_matchers()
    return online[0] if online else None


# -- AI Sort Assistant: job queue, matcher pulls -------------------------------
#
# Some matcher machines can reach a NAS over Tailscale but the NAS can't open a
# connection back out to them (one-way reachability, seen on at least one NAS's
# Docker/Tailscale setup) -- while the reverse direction (matcher -> NAS) always
# works, since that's how heartbeats already get through. So instead of the NAS
# calling out to start or poll a job, the browser just queues a job here; the
# matcher polls for queued jobs and pushes its own progress back, using only the
# connection direction that's actually reliable.

_ai_jobs: dict = {}
_ai_jobs_mu = threading.Lock()
_AI_JOB_MAX_AGE = 3600  # prune finished jobs older than this whenever a new one is queued
# If the matcher machine sleeps, crashes, or restarts mid-job, its worker thread just
# vanishes -- there's nothing left to ever mark the job done or errored. Without this,
# the job sits "in progress" forever with no explanation.
#
# Job-update pushes alone are the WRONG signal for "is the matcher still alive" --
# some matcher machines only reach a NAS over a flaky link, so individual pushes can
# lag or fail for minutes at a time even while the matcher is working completely
# fine. The heartbeat (separate, 15s interval, already proven reliable everywhere
# else in this file) is a much better liveness signal: as long as it's still
# arriving, give the job as much patience as it needs. Only declare a job dead if
# updates have gone quiet for a while AND the matcher itself has dropped off the
# heartbeat registry -- or, as an absolute last resort, if a single job has been
# running so long that something must have gotten stuck regardless of heartbeats.
_AI_JOB_STALE_TIMEOUT = 150
_AI_JOB_ABSOLUTE_TIMEOUT = 1800  # 30 min backstop even if heartbeats keep flowing


def _enqueue_ai_job(job_type, registry_dirs, unsorted_dir=None, max_refs_per_lifter=12):
    with _ai_jobs_mu:
        stale = [k for k, j in _ai_jobs.items() if j['done'] and time.time() - j['created'] > _AI_JOB_MAX_AGE]
        for k in stale:
            del _ai_jobs[k]
        job_id = uuid.uuid4().hex[:8]
        now = time.time()
        _ai_jobs[job_id] = {
            'type': job_type,
            'registry_dirs': registry_dirs,
            'unsorted_dir': unsorted_dir,
            'max_refs_per_lifter': max_refs_per_lifter,
            'status': 'queued',   # 'queued' -> 'claimed' (matcher picked it up) -> 'done'
            'progress': 0.0,
            'message': 'queued',
            'done': False,
            'error': None,
            'result': None,
            'created': now,
            'last_update': now,
        }
    return job_id


def _ai_job_view(job):
    # Caller already holds _ai_jobs_mu.
    if not job['done']:
        now = time.time()
        quiet_too_long = now - job['last_update'] > _AI_JOB_STALE_TIMEOUT
        no_heartbeat = not _active_matcher()
        absolute_timeout = now - job['created'] > _AI_JOB_ABSOLUTE_TIMEOUT
        if (quiet_too_long and no_heartbeat) or absolute_timeout:
            job['done'] = True
            job['status'] = 'done'
            job['error'] = 'Lost contact with the AI Sort machine — it may have gone to sleep or restarted. Try again.'
    return {k: job[k] for k in ('progress', 'message', 'done', 'error', 'result')}


@app.route('/api/ai-sort/start', methods=['POST'])
def ai_sort_start():
    # Body: {registry_dirs: [...], unsorted_dir, max_refs_per_lifter?} -- paths
    # relative to BASE, same convention as every other folder-taking endpoint.
    # registry_dirs can be one parent folder whose subfolders are athletes, several
    # such parents (e.g. Flight A + Flight B selected together), several
    # individually-selected athlete folders, or a mix -- grouping auto-detects this on
    # the matcher side. Queues the job for the matcher to pick up and returns its
    # job_id for polling -- see the _ai_jobs comment above for why it's a queue
    # instead of a direct call.
    data = request.get_json(force=True, silent=True) or {}
    registry_dirs = data.get('registry_dirs') or []
    unsorted_dir = data.get('unsorted_dir', '')
    if not registry_dirs or not unsorted_dir:
        return jsonify({'error': 'registry_dirs and unsorted_dir are required'}), 400
    base_r = str(BASE.resolve())
    for rel in (*registry_dirs, unsorted_dir):
        full = (BASE / rel).resolve()
        if not str(full).startswith(base_r) or not full.is_dir():
            return jsonify({'error': f'Folder not found: {rel}'}), 404
    if not _active_matcher():
        return jsonify({'error': 'No AI Sort Assistant machine currently online'}), 503
    job_id = _enqueue_ai_job('analyze', registry_dirs, unsorted_dir, data.get('max_refs_per_lifter', 12))
    return jsonify({'job_id': job_id})


@app.route('/api/ai-sort/status/<job_id>')
def ai_sort_status(job_id):
    with _ai_jobs_mu:
        job = _ai_jobs.get(job_id)
        if job is None:
            abort(404)
        return jsonify(_ai_job_view(job))


@app.route('/api/ai-sort/prebuild', methods=['POST'])
def ai_sort_prebuild():
    # Body: {registry_dirs: [...], max_refs_per_lifter?} -- fired the moment athlete
    # folders are chosen in the sidebar (right-click "Use as"/"Add to"), ahead of
    # clicking Start Analysis, so the gallery is often already built by the time the
    # unsorted folder is picked too. Fire-and-forget from the browser's side.
    data = request.get_json(force=True, silent=True) or {}
    registry_dirs = data.get('registry_dirs') or []
    if not registry_dirs:
        return jsonify({'error': 'registry_dirs is required'}), 400
    base_r = str(BASE.resolve())
    for rel in registry_dirs:
        full = (BASE / rel).resolve()
        if not str(full).startswith(base_r) or not full.is_dir():
            return jsonify({'error': f'Folder not found: {rel}'}), 404
    if not _active_matcher():
        return jsonify({'error': 'No AI Sort Assistant machine currently online'}), 503
    job_id = _enqueue_ai_job('prebuild', registry_dirs, None, data.get('max_refs_per_lifter', 12))
    return jsonify({'job_id': job_id})


@app.route('/api/ai-sort/prebuild-status/<job_id>')
def ai_sort_prebuild_status(job_id):
    with _ai_jobs_mu:
        job = _ai_jobs.get(job_id)
        if job is None:
            abort(404)
        return jsonify(_ai_job_view(job))


@app.route('/api/matcher/next-job')
def api_matcher_next_job():
    # Matcher-key gated (not session): the matcher polls this for work instead of
    # the NAS calling out to it -- see the _ai_jobs comment above.
    if not hmac.compare_digest(request.headers.get('X-Matcher-Key', ''), MATCHER_KEY):
        abort(403)
    with _ai_jobs_mu:
        queued = sorted(
            ((jid, j) for jid, j in _ai_jobs.items() if j['status'] == 'queued'),
            key=lambda kv: kv[1]['created'],
        )
        if not queued:
            return jsonify({})
        job_id, job = queued[0]
        job['status'] = 'claimed'
        return jsonify({
            'job_id': job_id,
            'type': job['type'],
            'registry_dirs': job['registry_dirs'],
            'unsorted_dir': job['unsorted_dir'],
            'max_refs_per_lifter': job['max_refs_per_lifter'],
        })


@app.route('/api/matcher/job-update/<job_id>', methods=['POST'])
def api_matcher_job_update(job_id):
    # Matcher-key gated (not session): the matcher pushes its own progress and
    # results back here as it works, instead of the NAS polling the matcher for
    # them -- see the _ai_jobs comment above.
    if not hmac.compare_digest(request.headers.get('X-Matcher-Key', ''), MATCHER_KEY):
        abort(403)
    data = request.get_json(force=True, silent=True) or {}
    with _ai_jobs_mu:
        job = _ai_jobs.get(job_id)
        if job is None:
            abort(404)
        for k in ('progress', 'message', 'done', 'error', 'result'):
            if k in data:
                job[k] = data[k]
        job['last_update'] = time.time()
        if job.get('done'):
            job['status'] = 'done'
    return jsonify({'ok': True})

_TS_RE = re.compile(rb'(\d{4}):(\d{2}):(\d{2}) (\d{2}):(\d{2}):(\d{2})')

def _read_ts(path: Path) -> int | None:
    try:
        with path.open('rb') as f:
            data = f.read(8192)
        m = _TS_RE.search(data)
        if m:
            s = b'%s:%s:%s %s:%s:%s' % m.groups()
            return int(time.mktime(time.strptime(s.decode(), '%Y:%m:%d %H:%M:%S')))
    except Exception:
        pass
    try:
        return int(path.stat().st_mtime)
    except Exception:
        return None

_locks: dict[str, threading.Lock] = {}
_locks_mu = threading.Lock()

# App-wide cap on concurrent thumbnail generation (exiftool/ffmpeg subprocesses are
# CPU-heavy; without this, a burst of on-demand loads when opening a big folder for
# the first time can saturate the NAS's CPU and starve unrelated requests). The NAS
# has plenty of headroom for this (12 cores, this container using well under its
# memory cap), so this can run higher than the old, more conservative value.
_thumb_gen_sema = threading.BoundedSemaphore(8)

# Bulk background work (a "Generate Cache" run, the small-cache regenerate job, the
# periodic watched-folder sync) can otherwise saturate every core with exiftool/
# ffmpeg subprocesses, making an interactive request -- browsing a folder, double-
# clicking a photo to view it full-size -- wait in line behind a queue of background
# work for CPU time even though nobody's actively looking at those bulk-job files
# right now. _priority_local marks "this thread is doing background bulk work" (set
# once at the top of each bulk worker's per-item function); _run then lowers OS
# scheduling priority (nice) for just that subprocess call, so the Linux scheduler
# naturally favours interactive requests -- which stay at normal priority,
# unaffected -- whenever the two are competing for the same CPU.
_priority_local = threading.local()

def _run(cmd: list[str], **kwargs):
    preexec = (lambda: os.nice(15)) if getattr(_priority_local, 'background', False) else None
    return subprocess.run(cmd, preexec_fn=preexec, **kwargs)


_LARGE_CACHE_JOB_THRESHOLD = 2000  # files -- above this, a Generate Cache job is treated
# as bulk background work rather than a fast, actively-awaited request. Well below what a
# single event folder is (150k+ is normal), well above a normal "cache this one folder
# I'm about to use" click.

def _wait_for_load_headroom():
    """Block briefly while the system is under heavy load, so large/bulk background
    cache work (a big "Generate Cache" run, the watched-folder resync) yields to
    interactive use instead of competing with it -- full speed resumes automatically
    once the NAS is quiet again (e.g. overnight, or any other lull), no fixed schedule
    needed. os.nice() alone only affects CPU *scheduling preference*, not whether the
    work happens at all -- on a NAS with many cores, a big job can still keep every
    core busy enough to make simple, cheap requests (like a folder listing) feel slow
    just from sheer contention. This adds an actual pause, not just a lower priority."""
    try:
        cpu_count = os.cpu_count() or 4
    except Exception:
        cpu_count = 4
    backoff = 0.5
    while True:
        try:
            load1, _, _ = os.getloadavg()
        except (OSError, AttributeError):
            return  # not available on this platform -- don't block
        if load1 < cpu_count * 0.75:
            return
        time.sleep(backoff)
        backoff = min(backoff * 1.5, 5.0)


class _ExifToolWorker:
    """One persistent `exiftool -stay_open` process. A fresh exiftool invocation
    pays Perl's interpreter startup cost (~140ms measured on this NAS) on every
    single call; a warm persistent process answers the same call in ~10-15ms.
    Each RAW photo needs 2-3 of these calls (orientation, plus one or two preview-
    extraction attempts depending on the camera), so this is the single biggest
    lever on thumbnail-generation speed. Exclusive use is enforced by the pool's
    Queue-based checkout (see _ExifToolPool), not by a lock here."""

    def __init__(self):
        self.proc = None
        self._seq = 0

    def _ensure_started(self):
        if self.proc is None or self.proc.poll() is not None:
            self.proc = subprocess.Popen(
                ['exiftool', '-stay_open', 'True', '-@', '-'],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            )

    def run(self, args: list[str], timeout: float = 20) -> bytes | None:
        """Runs one exiftool command through this persistent process. Returns the
        raw stdout bytes (matching what `subprocess.run(['exiftool', *args]).stdout`
        would give), or None if the worker is unhealthy/times out -- callers should
        fall back to a one-off exiftool call in that case, never treat None as
        "ran successfully with empty output"."""
        try:
            self._ensure_started()
            self._seq += 1
            tag = self._seq
            cmd = ('\n'.join(args) + f'\n-execute{tag}\n').encode()
            self.proc.stdin.write(cmd)
            self.proc.stdin.flush()
            # exiftool echoes back a "{ready<N>}" line once that command's output is
            # fully written -- using a per-call number (rather than a bare "{ready}")
            # means this can never be confused with that exact byte sequence turning
            # up inside actual binary image data being extracted.
            sentinel = f'{{ready{tag}}}'.encode()
            out = bytearray()
            # readline() is a blocking call with no timeout of its own -- if exiftool
            # never writes the sentinel (seen in practice: a worker can go quietly
            # unresponsive under concurrent load without crashing or exiting), the
            # time-check below never gets re-evaluated because the thread is frozen
            # inside that one blocking read, not looping. A watchdog timer is a hard
            # backstop: it kills the process if the whole call overruns its timeout,
            # which forces readline() to return (EOF) so this can't hang forever.
            proc = self.proc
            def _kill_on_timeout():
                try:
                    proc.kill()
                except Exception:
                    pass
            watchdog = threading.Timer(timeout, _kill_on_timeout)
            watchdog.start()
            try:
                while True:
                    line = proc.stdout.readline()
                    if not line:
                        raise RuntimeError('exiftool worker exited')
                    if line.rstrip(b'\r\n') == sentinel:
                        break
                    out += line
            finally:
                watchdog.cancel()
            return bytes(out)
        except Exception:
            try:
                if self.proc:
                    self.proc.kill()
            except Exception:
                pass
            self.proc = None
            return None


class _ExifToolPool:
    """A small pool of _ExifToolWorker processes, checked out via a Queue so each
    is only ever used by one caller at a time (avoids interleaving separate
    commands' output on one process's stdin/stdout). Sized to match
    _thumb_gen_sema so the pool itself never becomes the bottleneck at that
    concurrency level. If the pool can't supply a worker (all busy past the
    timeout, or every worker is unhealthy), callers fall back to a fresh one-off
    exiftool process -- slower for that one call, but never a hard failure."""

    def __init__(self, size: int):
        self._size = size
        self._q: queue.Queue = queue.Queue()
        self._init_lock = threading.Lock()
        self._ready = False

    def _ensure_init(self):
        if self._ready:
            return
        with self._init_lock:
            if self._ready:
                return
            for _ in range(self._size):
                self._q.put(_ExifToolWorker())
            self._ready = True

    def run(self, args: list[str], timeout: float = 20) -> bytes | None:
        self._ensure_init()
        try:
            worker = self._q.get(timeout=timeout)
        except queue.Empty:
            return None
        try:
            return worker.run(args, timeout=timeout)
        finally:
            self._q.put(worker)


_exiftool_pool = _ExifToolPool(size=8)


def _run_exiftool(args: list[str], timeout: float = 20) -> bytes | None:
    """Runs a fresh one-off exiftool process every call. The persistent
    -stay_open pool (_exiftool_pool, still defined above) was meant to skip
    Perl's ~140ms startup cost, but under real concurrent load its workers were
    observed going quietly unresponsive without crashing or exiting -- every
    call then burns its full timeout waiting on a stuck worker before falling
    back here anyway, which is far *slower* overall than never using the pool.
    Disabled until that's root-caused; a slower-but-reliable thumbnail
    generation beats a faster-but-flaky one every time. Returns stdout bytes on
    success, or None on any failure (never raises)."""
    try:
        r = _run(['exiftool'] + args, capture_output=True, timeout=timeout)
        return r.stdout if r.returncode == 0 else None
    except Exception:
        return None

_jobs: dict[str, dict] = {}
_jobs_mu = threading.Lock()

_copy_jobs: dict[str, dict] = {}
_copy_jobs_mu = threading.Lock()

_listing_cache: dict[str, dict] = {}  # path_str → {data, ts}
_LISTING_TTL = 300  # seconds (5 min — re-scan only if stale or after a move)

_dir_tree: dict[str, list] = {}   # abs path_str → [{name, hasChildren}, ...]
_dir_file_counts: dict[str, dict] = {}  # abs path_str → {p, v} direct counts
_dir_tree_mu = threading.Lock()
_tree_ready = False                # True after first full walk completes
_DIR_TREE_REFRESH = 60             # re-scan every minute
_watcher_progress = {'running': False, 'done': 0, 'total': 0, 'last_sync': 0}
_watcher_mu = threading.Lock()


_SKIP_DIRS = {'.wlm_thumbs', '.wlm_trash', '@Recycle', '@Recently-Snapshot', '@eaDir'}

def _build_dir_tree():
    """Walk the photos directory and populate the folder-structure cache."""
    new_tree: dict[str, list] = {}
    new_counts: dict[str, dict] = {}
    try:
        for root, dirs, files in os.walk(str(BASE)):
            dirs[:] = sorted((d for d in dirs if not d.startswith('.') and d not in _SKIP_DIRS), key=_nat)
            root_path = Path(root)
            # Count media files directly in this directory
            p = sum(1 for f in files if not f.startswith('.') and Path(f).suffix.lower() in PHOTO_EXTS)
            v = sum(1 for f in files if not f.startswith('.') and Path(f).suffix.lower() in VIDEO_EXTS)
            if p or v:
                new_counts[str(root_path)] = {'p': p, 'v': v}
            children = []
            for d in dirs:
                child = root_path / d
                try:
                    has_children = any(
                        p2.is_dir() and not p2.name.startswith('.')
                        for p2 in child.iterdir()
                    )
                except OSError:
                    has_children = False
                children.append({'name': d, 'hasChildren': has_children})
            new_tree[str(root_path)] = children
    except Exception:
        pass
    global _tree_ready
    with _dir_tree_mu:
        _dir_tree.clear()
        _dir_tree.update(new_tree)
        _dir_file_counts.clear()
        _dir_file_counts.update(new_counts)
    _tree_ready = True


def _dir_tree_loop():
    time.sleep(2)           # brief pause so Flask finishes binding the port
    while True:
        _build_dir_tree()
        time.sleep(_DIR_TREE_REFRESH)




def _invalidate_listing(folder_path: Path):
    key = str(folder_path.resolve())
    _listing_cache.pop(key, None)
    # also invalidate parent so its listing (which may include file counts) refreshes
    _listing_cache.pop(str(folder_path.resolve().parent), None)


def _invalidate_dir_tree(path: Path):
    """Remove cached entries for a path and its parent so the next ls and count is fresh."""
    with _dir_tree_mu:
        _dir_tree.pop(str(path), None)
        _dir_tree.pop(str(path.parent), None)
        _dir_file_counts.pop(str(path), None)
        _dir_file_counts.pop(str(path.parent), None)


def _lock(key: str) -> threading.Lock:
    with _locks_mu:
        if key not in _locks:
            _locks[key] = threading.Lock()
        return _locks[key]


def _thumb_path(rel: str) -> Path:
    return THUMB_DIR / (rel.lstrip('/') + '.jpg')


def _make_thumb(src: Path, dst: Path) -> bool:
    with _thumb_gen_sema:
        return _make_thumb_impl(src, dst)


def _make_thumb_impl(src: Path, dst: Path) -> bool:
    dst.parent.mkdir(parents=True, exist_ok=True)
    ext = src.suffix.lower()
    size = _cur_thumb_size()
    quality = _cur_thumb_quality()
    try:
        if ext in RAW_EXTS:
            # Extract embedded JPEG preview — camera already baked one in, ~100x faster than decoding RAW
            if HAS_PILLOW:
                # Read orientation from the RAW file itself (embedded JPEGs often lack this tag)
                raw_orient = 1
                try:
                    ro_out = _run_exiftool(['-Orientation#', '-s3', str(src)], timeout=5)
                    ro_str = ro_out.decode(errors='ignore').strip() if ro_out is not None else ''
                    if ro_str.isdigit():
                        raw_orient = int(ro_str)
                except Exception:
                    pass
                # -ThumbnailImage is the last resort: much lower resolution than a
                # real preview, but some RAW formats (confirmed: Panasonic .rw2)
                # only embed this and never JpegFromRaw/PreviewImage, which
                # otherwise means a total 500 on every file of that type — no
                # thumbnail is a much worse outcome than a small one.
                for tag in ('-JpegFromRaw', '-PreviewImage', '-ThumbnailImage'):
                    try:
                        r_out = _run_exiftool(['-b', tag, str(src)], timeout=30)
                        if r_out is not None and len(r_out) > 2000:
                            with Image.open(BytesIO(r_out)) as img:
                                # Check if the embedded JPEG has its own orientation EXIF
                                try:
                                    jpeg_exif = img._getexif() or {}
                                    jpeg_orient = jpeg_exif.get(0x0112, 1)
                                except Exception:
                                    jpeg_orient = 1
                                if jpeg_orient != 1:
                                    # JPEG knows its own orientation — trust it
                                    img = ImageOps.exif_transpose(img)
                                elif raw_orient in _EXIF_ORIENT_OPS:
                                    # JPEG has no orientation data — use RAW EXIF
                                    img = img.transpose(_EXIF_ORIENT_OPS[raw_orient])
                                img.thumbnail((size, size), Image.LANCZOS)
                                if img.mode != 'RGB':
                                    img = img.convert('RGB')
                                img.save(dst, 'JPEG', quality=quality, optimize=True)
                            return True
                    except Exception:
                        continue
            # Fallback: full RAW decode via ffmpeg
            _run(
                ['ffmpeg', '-y', '-threads', '2', '-i', str(src),
                 '-vframes', '1', '-vf', f'scale={size}:-2',
                 '-q:v', '5', str(dst)],
                capture_output=True, timeout=60
            )
            return dst.exists()
        elif ext in VIDEO_EXTS:
            _run(
                ['ffmpeg', '-y', '-threads', '2', '-ss', '2', '-i', str(src),
                 '-vframes', '1', '-vf', f'scale={size}:-2',
                 '-q:v', '5', str(dst)],
                capture_output=True, timeout=60
            )
            # Crop to 3:2 from centre (chop left/right of landscape frame)
            if dst.exists() and HAS_PILLOW:
                try:
                    with Image.open(dst) as img:
                        w, h = img.size
                        target_w = int(h * 1.5)
                        if target_w < w:
                            left = (w - target_w) // 2
                            img = img.crop((left, 0, left + target_w, h))
                            img.save(dst, 'JPEG', quality=quality, optimize=True)
                except Exception:
                    pass
            return dst.exists()
        elif HAS_PILLOW:
            with Image.open(src) as img:
                img = ImageOps.exif_transpose(img)
                img.thumbnail((size, size), Image.LANCZOS)
                if img.mode != 'RGB':
                    img = img.convert('RGB')
                img.save(dst, 'JPEG', quality=quality, optimize=True)
            return True
    except Exception:
        return False
    return False


def _serve_thumb(rel: str):
    src = BASE / rel
    if not src.is_file():
        abort(404)
    dst = _thumb_path(rel)
    need_gen = not dst.exists() or dst.stat().st_mtime < src.stat().st_mtime
    if need_gen:
        with _lock(rel):
            need_gen = not dst.exists() or dst.stat().st_mtime < src.stat().st_mtime
            if need_gen:
                ok = _make_thumb(src, dst)
                if not ok:
                    if src.suffix.lower() in JPEG_EXTS:
                        return send_file(src, mimetype='image/jpeg', conditional=True)
                    abort(500)
    return send_file(dst, mimetype='image/jpeg', conditional=True, max_age=1036800)


def clean_name(folder: str) -> str:
    return re.sub(r'^\d+\s*[-.]?\s*', '', folder).strip()


def list_dirs(path: Path) -> list[str]:
    try:
        return sorted(
            (e for e in os.listdir(path)
             if (path / e).is_dir() and not e.startswith('.')),
            key=_nat
        )
    except OSError:
        return []


def list_media(path: Path) -> list[str]:
    try:
        return sorted(
            e for e in os.listdir(path)
            if (path / e).is_file() and Path(e).suffix.lower() in MEDIA_EXTS
        )
    except OSError:
        return []


def _safe_resolve(rel_path: str, allowed_exts: set[str]):
    full = (BASE / rel_path).resolve()
    if not str(full).startswith(str(BASE.resolve())):
        abort(403)
    if full.suffix.lower() not in allowed_exts:
        abort(403)
    if not full.is_file():
        abort(404)
    return full


def _resolve_dir(rel_path: str = '') -> Path:
    base_r = BASE.resolve()
    full = (BASE / rel_path).resolve() if rel_path else base_r
    if not str(full).startswith(str(base_r)):
        abort(403)
    if not full.is_dir():
        abort(404)
    return full


def _resolve_dir_safe(rel_path: str = '') -> Path | None:
    try:
        base_r = BASE.resolve()
        full = (BASE / rel_path).resolve() if rel_path else base_r
        if not str(full).startswith(str(base_r)):
            return None
        return full if full.is_dir() else None
    except Exception:
        return None


def _load_ratings(folder_path: Path) -> dict:
    rfile = folder_path / '.wlm_ratings.json'
    try:
        return json.loads(rfile.read_text()) if rfile.is_file() else {}
    except Exception:
        return {}


# ── Cache metadata ────────────────────────────────────────────────────────────

def _load_cache_meta() -> dict:
    try:
        if CACHE_META_FILE.is_file():
            return json.loads(CACHE_META_FILE.read_text())
    except Exception:
        pass
    return {'folders': {}, 'cleanup_log': []}


def _save_cache_meta(meta: dict):
    CACHE_META_FILE.parent.mkdir(parents=True, exist_ok=True)
    CACHE_META_FILE.write_text(json.dumps(meta, indent=2))


def _cleanup_expired_caches():
    meta = _load_cache_meta()
    cutoff = time.time() - CACHE_EXPIRY_DAYS * 86400
    cleaned = []
    for folder, info in list(meta.get('folders', {}).items()):
        if info.get('watched'):
            continue  # watched folders never expire
        if info.get('cached_at', 0) < cutoff:
            thumb_folder = THUMB_DIR / folder
            count = 0
            if thumb_folder.exists():
                count = sum(1 for _ in thumb_folder.rglob('*.jpg'))
                shutil.rmtree(str(thumb_folder), ignore_errors=True)
            cleaned.append({'folder': folder, 'cleaned_at': int(time.time()), 'count': count})
            del meta['folders'][folder]
    if cleaned:
        meta.setdefault('cleanup_log', []).extend(cleaned)
        meta['cleanup_log'] = meta['cleanup_log'][-50:]
        _save_cache_meta(meta)
    return cleaned


# ── Cache worker ──────────────────────────────────────────────────────────────

def _cache_folder_worker(job_id: str, folder: str):
    path = _resolve_dir_safe(folder)
    if path is None:
        with _jobs_mu:
            _jobs[job_id].update({'finished': True, 'error': 'Folder not found'})
        return

    media_files = []
    for root, dirs, files in os.walk(str(path)):
        dirs[:] = sorted((d for d in dirs if not d.startswith('.')), key=_nat)
        root_path = Path(root)
        for f in sorted(files):
            if f.startswith('.'):
                continue
            if Path(f).suffix.lower() in MEDIA_EXTS:
                media_files.append(str((root_path / f).relative_to(BASE)))

    total = len(media_files)
    with _jobs_mu:
        _jobs[job_id]['total'] = total

    # A big event is routinely 150k+ files -- a job that size behaves like background
    # bulk work (lower OS priority, yields to load) instead of running full-tilt, so it
    # doesn't compete with people actively sorting. A normal-sized job (someone
    # right-clicking a specific folder they're about to use) stays fast and at full
    # priority, since that's almost always a direct request someone is waiting on.
    is_large = total > _LARGE_CACHE_JOB_THRESHOLD

    done_count = 0
    error_count = 0
    count_lock = threading.Lock()

    def _process(rel):
        nonlocal done_count, error_count
        if is_large:
            _priority_local.background = True
            _wait_for_load_headroom()
        src = BASE / rel
        dst = _thumb_path(rel)
        if not dst.exists() or dst.stat().st_mtime < src.stat().st_mtime:
            ok = _make_thumb(src, dst)
        else:
            ok = True
        with count_lock:
            done_count += 1
            if not ok:
                error_count += 1
            with _jobs_mu:
                _jobs[job_id]['done'] = done_count
                _jobs[job_id]['errors'] = error_count

    with ThreadPoolExecutor(max_workers=4) as pool:
        pool.map(_process, media_files)

    meta = _load_cache_meta()
    prev = meta.setdefault('folders', {}).get(folder, {})
    meta['folders'][folder] = {
        'cached_at': int(time.time()),
        'count': done_count - error_count,
        'watched': prev.get('watched', True),  # keep watched state; default True on first cache
    }
    _save_cache_meta(meta)

    with _jobs_mu:
        _jobs[job_id]['finished'] = True


def _regenerate_all_worker(job_id: str, folders: list):
    """Re-caches every previously-cached folder from scratch, at whatever size/
    quality is currently configured -- used when the small-cache toggle changes,
    since existing thumbnails don't get touched just by flipping the setting
    (the mtime check in _serve_thumb would otherwise leave old-size thumbnails
    sitting there indefinitely). Each file is regenerated to a temp path and
    atomically swapped into place only once ready, so the existing thumbnail
    keeps serving normally right up until the instant its replacement is
    available -- no gap where a previously-cached file is suddenly missing, and
    a failed regenerate just leaves the old thumbnail in place instead of
    nothing at all."""
    media_files = []
    for folder in folders:
        path = _resolve_dir_safe(folder)
        if path is None:
            continue
        for root, dirs, files in os.walk(str(path)):
            dirs[:] = sorted((d for d in dirs if not d.startswith('.')), key=_nat)
            root_path = Path(root)
            for f in sorted(files):
                if f.startswith('.'):
                    continue
                if Path(f).suffix.lower() in MEDIA_EXTS:
                    media_files.append(str((root_path / f).relative_to(BASE)))

    total = len(media_files)
    with _jobs_mu:
        _jobs[job_id]['total'] = total

    done_count = 0
    error_count = 0
    count_lock = threading.Lock()

    def _process(rel):
        nonlocal done_count, error_count
        _priority_local.background = True
        _wait_for_load_headroom()
        src = BASE / rel
        dst = _thumb_path(rel)
        tmp = dst.with_name(dst.name + f'.regen{job_id}.tmp')
        ok = _make_thumb(src, tmp)
        if ok and tmp.exists():
            try:
                os.replace(str(tmp), str(dst))  # atomic on the same filesystem
            except OSError:
                ok = False
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass
        with count_lock:
            done_count += 1
            if not ok:
                error_count += 1
            with _jobs_mu:
                _jobs[job_id]['done'] = done_count
                _jobs[job_id]['errors'] = error_count

    with ThreadPoolExecutor(max_workers=4) as pool:
        pool.map(_process, media_files)

    meta = _load_cache_meta()
    now = int(time.time())
    for folder in folders:
        if folder in meta.get('folders', {}):
            meta['folders'][folder]['cached_at'] = now
    _save_cache_meta(meta)

    with _jobs_mu:
        _jobs[job_id]['finished'] = True


# ── Background watcher ───────────────────────────────────────────────────────

WATCH_INTERVAL = 30  # seconds

def _watch_tick():
    meta = _load_cache_meta()
    # Collect all pending files across all watched folders
    folder_pending: dict[str, list] = {}
    for folder, info in meta.get('folders', {}).items():
        if not info.get('watched'):
            continue
        path = _resolve_dir_safe(folder)
        if path is None:
            continue
        pending = []
        for root, dirs, files in os.walk(str(path)):
            dirs[:] = sorted((d for d in dirs if not d.startswith('.')), key=_nat)
            root_path = Path(root)
            for f in files:
                if f.startswith('.') or Path(f).suffix.lower() not in MEDIA_EXTS:
                    continue
                rel = str((root_path / f).relative_to(BASE))
                dst = _thumb_path(rel)
                if not dst.exists() or dst.stat().st_mtime < (BASE / rel).stat().st_mtime:
                    pending.append(rel)
        if pending:
            folder_pending[folder] = pending
    all_pending = [(rel, fk) for fk, rels in folder_pending.items() for rel in rels]
    if not all_pending:
        with _watcher_mu:
            _watcher_progress.update({'running': False, 'last_sync': int(time.time())})
        return
    with _watcher_mu:
        _watcher_progress.update({'running': True, 'done': 0, 'total': len(all_pending)})
    done_count = 0
    folder_done: dict[str, int] = {}
    count_lock = threading.Lock()
    def _process(item):
        nonlocal done_count
        _priority_local.background = True
        _wait_for_load_headroom()
        rel, fk = item
        ok = _make_thumb(BASE / rel, _thumb_path(rel))
        with count_lock:
            done_count += 1
            if ok:
                folder_done[fk] = folder_done.get(fk, 0) + 1
            with _watcher_mu:
                _watcher_progress['done'] = done_count
    with ThreadPoolExecutor(max_workers=4) as pool:
        pool.map(_process, all_pending)
    with _watcher_mu:
        _watcher_progress.update({'running': False, 'last_sync': int(time.time())})
    if any(folder_done.values()):
        meta = _load_cache_meta()
        for fk, cnt in folder_done.items():
            if cnt and fk in meta.get('folders', {}):
                meta['folders'][fk]['count'] = meta['folders'][fk].get('count', 0) + cnt
        _save_cache_meta(meta)


def _watcher_loop():
    while True:
        time.sleep(WATCH_INTERVAL)
        try:
            _watch_tick()
        except Exception:
            pass


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/push', methods=['POST'])
def push_template():
    """One-time upload endpoint: curl -X POST /push --data-binary @index.html"""
    content = request.get_data()
    if not content:
        abort(400)
    target = Path(__file__).parent / 'templates' / 'index.html'
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(content)
    return f'ok — wrote {len(content)} bytes to {target}\n'


@app.route('/logo')
def logo():
    if LOGO_PATH.is_file():
        return send_file(LOGO_PATH, mimetype='image/png')
    abort(404)


@app.route('/api/search-folders')
def search_folders():
    q = request.args.get('q', '').strip().lower()
    if not q:
        return jsonify([])
    base_str = str(BASE)
    results = []
    with _dir_tree_mu:
        for parent_str, children in _dir_tree.items():
            # skip NAS system/recycle folders
            rel_parent = parent_str[len(base_str):].lstrip('/')
            if any(seg in _SKIP_DIRS for seg in rel_parent.split('/')):
                continue
            for child in children:
                if child['name'] in _SKIP_DIRS:
                    continue
                if q in child['name'].lower():
                    full = parent_str + '/' + child['name']
                    rel = full[len(base_str):].lstrip('/') if full.startswith(base_str) else full
                    results.append({'name': child['name'], 'path': rel})
    results.sort(key=lambda x: _nat(x['name']))
    return jsonify(results[:60])



@app.route('/api/ls')
@app.route('/api/ls/<path:folder>')
def ls(folder=''):
    path = _resolve_dir(folder)
    # Always read from disk so newly created folders appear immediately
    result = []
    for name in list_dirs(path):
        child = path / name
        try:
            has_children = any(
                p.is_dir() and not p.name.startswith('.')
                for p in child.iterdir()
            )
        except OSError:
            has_children = False
        result.append({'name': name, 'hasChildren': has_children})
    with _dir_tree_mu:
        _dir_tree[str(path)] = result
    return jsonify(result)


@app.route('/api/preview/<path:folder>')
def preview(folder):
    media_exts = JPEG_EXTS | RAW_EXTS
    path = _resolve_dir(folder)
    files = []
    try:
        files = sorted(
            (f for f in os.listdir(path)
             if not f.startswith('.') and Path(f).suffix.lower() in media_exts
             and (path / f).is_file()),
            key=_nat
        )
    except OSError:
        pass
    if not files:
        for sub in list_dirs(path):
            sub_path = path / sub
            try:
                files = sorted(
                    (f for f in os.listdir(sub_path)
                     if not f.startswith('.') and Path(f).suffix.lower() in media_exts
                     and (sub_path / f).is_file()),
                    key=_nat
                )
            except OSError:
                pass
            if files:
                path = sub_path
                break
    if not files:
        abort(404)
    first = str((path / files[0]).relative_to(BASE))
    second_idx = min(3, len(files) - 1)
    result = {'path': first}
    if second_idx > 0:
        result['second'] = str((path / files[second_idx]).relative_to(BASE))
    return jsonify(result)


@app.route('/api/cache-dir')
def cache_dir():
    smb_path = str(THUMB_DIR).replace('/photos', '/Volumes/Public')
    return jsonify({'server_path': str(THUMB_DIR), 'smb_path': smb_path})


@app.route('/api/photos-in/<path:folder>')
def photos_in(folder):
    path = _resolve_dir(folder)
    path_key = str(path.resolve())
    limit = request.args.get('limit', 3000, type=int)
    now = time.time()

    nocache = request.args.get('nocache', '0') == '1'
    cached = _listing_cache.get(path_key)
    if not nocache and cached and (now - cached['ts']) < _LISTING_TTL and cached['data'].get('limit') == limit:
        return jsonify(cached['data'])

    entries: list[tuple[int, dict]] = []
    ratings_cache: dict[str, dict] = {}
    truncated = False

    for root, dirs, files in os.walk(str(path)):
        dirs[:] = sorted((d for d in dirs if not d.startswith('.')), key=_nat)
        root_path = Path(root)
        folder_key = str(root_path)
        if folder_key not in ratings_cache:
            ratings_cache[folder_key] = _load_ratings(root_path)
        ratings = ratings_cache[folder_key]
        athlete = clean_name(root_path.name)

        for f in sorted(files):
            if f.startswith('.'):
                continue
            ext = Path(f).suffix.lower()
            if ext in MEDIA_EXTS:
                if len(entries) >= limit:
                    truncated = True
                    break
                rel = str((root_path / f).relative_to(BASE))
                entry = ratings.get(f, {})
                ts = _read_ts(root_path / f) or 0
                entries.append((ts, {
                    'path':    rel,
                    'name':    f,
                    'type':    'video' if ext in VIDEO_EXTS else 'photo',
                    'athlete': athlete,
                    'rating':  entry.get('rating', 0),
                    'flag':    entry.get('flag', 'none'),
                    'label':   entry.get('label', 'none'),
                }))
        if truncated:
            break

    entries.sort(key=lambda x: x[0])
    result = [item for _, item in entries]

    data = {'items': result, 'truncated': truncated, 'limit': limit}
    _listing_cache[path_key] = {'data': data, 'ts': now}
    return jsonify(data)


@app.route('/api/matcher/photos-in/<path:folder>')
def api_matcher_photos_in(folder):
    # Matcher-key gated (not session): lets the matching engine list photos on a
    # machine with no share mounted, over the same key already used for heartbeats.
    if not hmac.compare_digest(request.headers.get('X-Matcher-Key', ''), MATCHER_KEY):
        abort(403)
    path = _resolve_dir(folder)
    items = []
    for root, dirs, files in os.walk(str(path)):
        dirs[:] = sorted((d for d in dirs if not d.startswith('.')), key=_nat)
        root_path = Path(root)
        for f in sorted(files):
            if f.startswith('.'):
                continue
            if Path(f).suffix.lower() in MEDIA_EXTS:
                fp = root_path / f
                items.append({'path': str(fp.relative_to(BASE)), 'name': f, 'ts': _read_ts(fp) or 0})
    return jsonify(items)


@app.route('/api/matcher/thumb/<path:rel_path>')
def api_matcher_thumb(rel_path):
    # Same cached 480px thumbnail the browser grid uses — matcher-key gated instead
    # of session, so analysis works without the NAS share mounted on that machine.
    if not hmac.compare_digest(request.headers.get('X-Matcher-Key', ''), MATCHER_KEY):
        abort(403)
    _safe_resolve(rel_path, MEDIA_EXTS)
    return _serve_thumb(rel_path)


@app.route('/thumb/<path:rel_path>')
def thumb(rel_path):
    _safe_resolve(rel_path, MEDIA_EXTS)
    return _serve_thumb(rel_path)


@app.route('/img/<path:rel_path>')
def image(rel_path):
    full = _safe_resolve(rel_path, JPEG_EXTS)
    return send_file(full, mimetype='image/jpeg', conditional=True)


@app.route('/preview/<path:rel_path>')
def preview_image(rel_path):
    """Full-resolution preview: serves JPEG directly, extracts embedded JPEG from RAW files."""
    full = (BASE / rel_path).resolve()
    base_r = str(BASE.resolve())
    if not str(full).startswith(base_r) or not full.is_file():
        abort(404)
    ext = full.suffix.lower()
    if ext in JPEG_EXTS:
        try:
            img = Image.open(full)
            img = ImageOps.exif_transpose(img)
            buf = BytesIO()
            img.save(buf, 'JPEG', quality=95)
            buf.seek(0)
            return send_file(buf, mimetype='image/jpeg', max_age=86400)
        except Exception:
            return send_file(full, mimetype='image/jpeg', conditional=True)
    elif ext in RAW_EXTS:
        for tag in ('-JpegFromRaw', '-PreviewImage'):
            try:
                r = _run(
                    ['exiftool', '-b', tag, str(full)],
                    capture_output=True, timeout=30
                )
                if r.returncode == 0 and len(r.stdout) > 2000:
                    img = Image.open(BytesIO(r.stdout))
                    img = ImageOps.exif_transpose(img)
                    buf = BytesIO()
                    img.save(buf, 'JPEG', quality=92)
                    buf.seek(0)
                    return send_file(buf, mimetype='image/jpeg', max_age=86400)
            except Exception:
                continue
        abort(404)
    else:
        abort(403)


@app.route('/api/move', methods=['POST'])
def move_files():
    data = request.get_json(force=True) or {}
    src_paths = data.get('paths', [])
    dst_folder = data.get('to', '')
    if not src_paths or not dst_folder:
        abort(400)
    base_r = str(BASE.resolve())
    try:
        dst_dir = _resolve_dir(dst_folder)
    except Exception:
        return jsonify({'moved': [], 'errors': src_paths, 'error': 'Target folder not found'})
    moved, errors = [], []
    src_dirs = set()
    for rel in src_paths:
        try:
            src = (BASE / rel).resolve()
            if not str(src).startswith(base_r) or not src.is_file():
                errors.append({'path': rel, 'reason': 'not_found'}); continue
            dst = dst_dir / src.name
            if dst.exists():
                errors.append({'path': rel, 'reason': 'duplicate', 'name': src.name}); continue
            src_dirs.add(src.parent)
            new_rel = str(dst.relative_to(BASE))
            old_thumb = _thumb_path(rel)
            src.rename(dst)
            # Carry the cached thumbnail along with the file it belongs to, instead of
            # leaving it orphaned at the old path -- a move shouldn't force a from-scratch
            # regeneration (a real ffmpeg re-extraction for video) of an unchanged image.
            if old_thumb.exists():
                new_thumb = _thumb_path(new_rel)
                try:
                    new_thumb.parent.mkdir(parents=True, exist_ok=True)
                    old_thumb.replace(new_thumb)
                except OSError:
                    pass
            moved.append(rel)
        except PermissionError:
            errors.append({'path': rel, 'reason': 'permission'})
        except Exception as ex:
            errors.append({'path': rel, 'reason': str(ex)})
    for d in src_dirs:
        _invalidate_listing(d)
        _invalidate_dir_tree(d)
    _invalidate_listing(dst_dir)
    _invalidate_dir_tree(dst_dir)
    return jsonify({'moved': moved, 'errors': errors})


@app.route('/thumb-at/<path:rel_path>')
def thumb_at(rel_path):
    """Return a video frame at a percentage through the file."""
    try:
        pct = min(max(float(request.args.get('pct', '20')), 0), 99)
    except ValueError:
        pct = 20.0
    src = BASE / rel_path
    if not src.is_file() or src.suffix.lower() not in VIDEO_EXTS:
        abort(404)
    dst = THUMB_DIR / (rel_path.lstrip('/') + f'.at{int(pct)}.jpg')
    need_gen = not dst.exists() or dst.stat().st_mtime < src.stat().st_mtime
    if need_gen:
        with _lock(f'{rel_path}@{pct}'):
            need_gen = not dst.exists() or dst.stat().st_mtime < src.stat().st_mtime
            if need_gen:
                dst.parent.mkdir(parents=True, exist_ok=True)
                try:
                    r = subprocess.run(
                        ['ffprobe', '-v', 'quiet', '-show_entries', 'format=duration',
                         '-of', 'csv=p=0', str(src)],
                        capture_output=True, text=True, timeout=10
                    )
                    ss = float(r.stdout.strip()) * pct / 100
                except Exception:
                    ss = 2.0
                subprocess.run(
                    ['ffmpeg', '-y', '-threads', '2', '-ss', str(ss), '-i', str(src),
                     '-vframes', '1', '-vf', f'scale={_cur_thumb_size()}:-2', '-q:v', '5', str(dst)],
                    capture_output=True, timeout=60
                )
    if dst.exists():
        return send_file(dst, mimetype='image/jpeg', conditional=True, max_age=1036800)
    abort(500)


@app.route('/video/<path:rel_path>')
def video(rel_path):
    full = _safe_resolve(rel_path, VIDEO_EXTS)
    return send_file(full, conditional=True)


# ── Cache endpoints ───────────────────────────────────────────────────────────

@app.route('/api/cache-folder/<path:folder>', methods=['POST'])
def api_cache_folder(folder):
    base_r = str(BASE.resolve())
    full = (BASE / folder).resolve()
    if not str(full).startswith(base_r) or not full.is_dir():
        abort(404)
    job_id = uuid.uuid4().hex[:8]
    with _jobs_mu:
        _jobs[job_id] = {'done': 0, 'total': 0, 'finished': False, 'errors': 0, 'folder': folder}
    threading.Thread(target=_cache_folder_worker, args=(job_id, folder), daemon=True).start()
    return jsonify({'job_id': job_id})


@app.route('/api/thumb-size-mode', methods=['GET', 'POST'])
def api_thumb_size_mode():
    global _small_cache_enabled
    regen_job_id = None
    if request.method == 'POST':
        data = request.get_json(force=True) or {}
        _small_cache_enabled = bool(data.get('small_cache', False))
        try:
            THUMB_DIR.mkdir(parents=True, exist_ok=True)
            THUMB_CONFIG_FILE.write_text(json.dumps({'small_cache': _small_cache_enabled}))
        except OSError:
            pass
        # Force-regenerate everything that was already cached, at the new size/quality --
        # flipping the setting alone wouldn't touch existing thumbnails otherwise.
        meta = _load_cache_meta()
        folders = list(meta.get('folders', {}).keys())
        if folders:
            regen_job_id = uuid.uuid4().hex[:8]
            with _jobs_mu:
                _jobs[regen_job_id] = {'done': 0, 'total': 0, 'finished': False, 'errors': 0, 'folder': 'All cached folders'}
            threading.Thread(target=_regenerate_all_worker, args=(regen_job_id, folders), daemon=True).start()
    return jsonify({
        'small_cache': _small_cache_enabled,
        'size': _cur_thumb_size(),
        'quality': _cur_thumb_quality(),
        'regen_job_id': regen_job_id,
    })


@app.route('/api/cache-job/<job_id>')
def api_cache_job(job_id):
    with _jobs_mu:
        if job_id not in _jobs:
            abort(404)
        return jsonify(dict(_jobs[job_id]))


_thumb_stats_cache = {'bytes': 0, 'count': 0, 'ts': 0}
_THUMB_STATS_TTL = 8  # seconds — avoid re-walking the whole cache dir on every poll

def _get_thumb_dir_stats() -> dict:
    now = time.time()
    if now - _thumb_stats_cache['ts'] < _THUMB_STATS_TTL:
        return {'bytes': _thumb_stats_cache['bytes'], 'count': _thumb_stats_cache['count']}
    total_bytes = 0
    total_count = 0
    for root, dirs, files in os.walk(str(THUMB_DIR)):
        for f in files:
            if f.endswith('.jpg'):
                try:
                    total_bytes += (Path(root) / f).stat().st_size
                    total_count += 1
                except OSError:
                    pass
    _thumb_stats_cache.update({'bytes': total_bytes, 'count': total_count, 'ts': now})
    return {'bytes': total_bytes, 'count': total_count}


@app.route('/api/cache-status')
def cache_status():
    with _watcher_mu:
        wp = dict(_watcher_progress)
    with _jobs_mu:
        active = [(jid, j) for jid, j in _jobs.items() if not j.get('finished')]
    if active:
        jid, job = active[0]
        wp['job'] = {'id': jid, 'done': job.get('done', 0), 'total': job.get('total', 0), 'folder': job.get('folder', '')}
    stats = _get_thumb_dir_stats()
    wp['nas_cache_bytes'] = stats['bytes']
    wp['nas_cache_count'] = stats['count']
    return jsonify(wp)


@app.route('/api/cache-info')
def api_cache_info():
    meta = _load_cache_meta()
    result = []
    for folder, info in meta.get('folders', {}).items():
        thumb_folder = THUMB_DIR / folder
        size = 0
        count = 0
        if thumb_folder.exists():
            for p in thumb_folder.rglob('*.jpg'):
                try:
                    size += p.stat().st_size
                    count += 1
                except OSError:
                    pass
        result.append({
            'folder':    folder,
            'cached_at': info.get('cached_at', 0),
            'count':     count,
            'size':      size,
            'watched':   info.get('watched', False),
        })
    return jsonify({
        'cached':      result,
        'cleanup_log': meta.get('cleanup_log', []),
    })


@app.route('/api/cache-watch/<path:folder>', methods=['DELETE'])
def api_cache_unwatch(folder):
    meta = _load_cache_meta()
    if folder in meta.get('folders', {}):
        meta['folders'][folder]['watched'] = False
        _save_cache_meta(meta)
    return jsonify({'ok': True, 'folder': folder})


@app.route('/api/cache-delete/<path:folder>', methods=['DELETE'])
def api_cache_delete(folder):
    thumb_folder = THUMB_DIR / folder
    count = 0
    if thumb_folder.exists():
        count = sum(1 for _ in thumb_folder.rglob('*.jpg'))
        shutil.rmtree(str(thumb_folder), ignore_errors=True)
    meta = _load_cache_meta()
    meta.get('folders', {}).pop(folder, None)
    _save_cache_meta(meta)
    return jsonify({'deleted': count, 'folder': folder})


@app.route('/api/cache-delete-all', methods=['DELETE'])
def api_cache_delete_all():
    meta = _load_cache_meta()
    total = 0
    for folder in list(meta.get('folders', {}).keys()):
        thumb_folder = THUMB_DIR / folder
        if thumb_folder.exists():
            total += sum(1 for _ in thumb_folder.rglob('*.jpg'))
            shutil.rmtree(str(thumb_folder), ignore_errors=True)
    meta['folders'] = {}
    _save_cache_meta(meta)
    return jsonify({'deleted': total})


def _wipe_all_cache() -> int:
    """Delete every cached thumbnail, including ones not tracked by the
    bulk-cache feature. Returns the number of thumbnails deleted. Factored
    out of the route so the client shell's own "Delete cache" button can
    call this directly in-process, without going through the login-gated
    HTTP endpoint."""
    count = 0
    if THUMB_DIR.exists():
        count = sum(1 for _ in THUMB_DIR.rglob('*.jpg'))
        shutil.rmtree(str(THUMB_DIR), ignore_errors=True)
        THUMB_DIR.mkdir(parents=True, exist_ok=True)
    _save_cache_meta({'folders': {}, 'cleanup_log': []})
    _thumb_stats_cache.update({'bytes': 0, 'count': 0, 'ts': time.time()})
    return count


@app.route('/api/cache-wipe-all', methods=['DELETE'])
def api_cache_wipe_all():
    """Delete every cached thumbnail, including ones not tracked by the bulk-cache feature."""
    return jsonify({'deleted': _wipe_all_cache()})


# ── Live system stats (CPU / network) ───────────────────────────────────────
# Real observed throughput rather than a synthetic speed test: running an
# actual bandwidth test continuously would itself compete with real sorting
# traffic for bandwidth, and only ever answers "how fast could this go" at
# the moment it ran. Reading the OS's actual byte counters is free, always
# current, and answers the question that's actually being asked — "is
# something moving slowly right now."
psutil.cpu_percent(interval=None)  # first call always returns 0 — prime it at import time
_net_io_last = {'ts': time.time(), 'bytes_sent': 0, 'bytes_recv': 0}
try:
    _io = psutil.net_io_counters()
    _net_io_last = {'ts': time.time(), 'bytes_sent': _io.bytes_sent, 'bytes_recv': _io.bytes_recv}
except Exception:
    pass


def _get_system_stats() -> dict:
    global _net_io_last
    cpu_percent = psutil.cpu_percent(interval=None)
    upload_mbps = download_mbps = 0.0
    try:
        now = time.time()
        io_now = psutil.net_io_counters()
        dt = max(now - _net_io_last['ts'], 0.001)
        upload_mbps = round((io_now.bytes_sent - _net_io_last['bytes_sent']) * 8 / dt / 1_000_000, 2)
        download_mbps = round((io_now.bytes_recv - _net_io_last['bytes_recv']) * 8 / dt / 1_000_000, 2)
        _net_io_last = {'ts': now, 'bytes_sent': io_now.bytes_sent, 'bytes_recv': io_now.bytes_recv}
    except Exception:
        pass
    with _jobs_mu:
        generating_cache = any(not j.get('finished', True) for j in _jobs.values())
    return {
        'cpu_percent': cpu_percent,
        'upload_mbps': max(upload_mbps, 0.0),
        'download_mbps': max(download_mbps, 0.0),
        'generating_cache': generating_cache,
    }


@app.route('/api/system-stats')
def api_system_stats():
    return jsonify(_get_system_stats())


@app.route('/api/timestamps/<path:folder>')
def api_timestamps(folder):
    path = _resolve_dir(folder)
    stem_ts: dict[str, int] = {}
    entries: list[tuple[str, str, Path]] = []

    for root, dirs, files in os.walk(str(path)):
        dirs[:] = sorted((d for d in dirs if not d.startswith('.')), key=_nat)
        root_path = Path(root)
        for f in sorted(files):
            if f.startswith('.'):
                continue
            p = Path(f)
            ext = p.suffix.lower()
            if ext not in MEDIA_EXTS:
                continue
            rel = str((root_path / f).relative_to(BASE))
            entries.append((rel, ext, root_path / f))
            if ext in JPEG_EXTS:
                ts = _read_ts(root_path / f)
                if ts:
                    stem_ts[p.stem] = ts

    result: dict[str, int] = {}
    for rel, ext, fp in entries:
        stem = Path(rel).stem
        if stem in stem_ts:
            result[rel] = stem_ts[stem]
        else:
            ts = _read_ts(fp)
            if ts:
                result[rel] = ts

    return jsonify(result)


@app.route('/api/exif/<path:rel_path>')
def api_exif(rel_path):
    fp = BASE / rel_path
    base_r = str(BASE.resolve())
    if not str(fp.resolve()).startswith(base_r) or not fp.is_file():
        abort(404)
    tags = [
        '-FileName', '-CreateDate', '-Model', '-LensModel',
        '-ShutterSpeed', '-ExposureTime', '-FNumber', '-Aperture',
        '-ISO', '-FocalLength', '-FocalLengthIn35mmFormat',
        '-ExposureMode', '-WhiteBalance', '-ImageWidth', '-ImageHeight',
        '-FileSize',
    ]
    try:
        r = subprocess.run(
            ['exiftool', '-j', '-d', '%Y-%m-%d %H:%M:%S'] + tags + [str(fp)],
            capture_output=True, text=True, timeout=10
        )
        if r.returncode == 0:
            return jsonify(json.loads(r.stdout)[0])
    except Exception:
        pass
    abort(500)


@app.route('/api/download-file/<path:rel_path>')
def api_download_file(rel_path):
    """GET-based single-file download for a plain <a href download> link, rather
    than /api/download's POST+fetch()+blob() path. That approach has to buffer
    the entire file in browser memory before anything happens -- on a slow
    connection with a large RAW/video file, that meant the UI went completely
    silent for the whole transfer (no progress at all) before the save dialog
    finally appeared. A native download link instead gets the browser's own
    download manager involved immediately: visible progress from the first
    byte, streamed straight to disk, and repeat clicks handled sanely by the
    browser rather than N parallel fetches all fighting over the same
    bandwidth. conditional=True adds Range support too, letting the browser
    show accurate progress via Content-Length."""
    base_r = str(BASE.resolve())
    full = (BASE / rel_path).resolve()
    if not str(full).startswith(base_r) or not full.is_file():
        abort(404)
    return send_file(str(full), as_attachment=True, download_name=full.name, conditional=True)


@app.route('/api/download', methods=['POST'])
def api_download():
    data = request.get_json(silent=True) or {}
    paths = data.get('paths', [])
    if not paths:
        abort(400)

    base_r = BASE.resolve()

    def _safe_file(rel):
        full = (BASE / rel).resolve()
        if not str(full).startswith(str(base_r)):
            return None
        return full if full.is_file() else None

    # A single file downloads as itself -- only bundle into a zip once there's
    # actually more than one, so a lone photo doesn't arrive wrapped in an
    # extra unzip step nobody asked for.
    if len(paths) == 1:
        fp = _safe_file(paths[0])
        if not fp:
            abort(404)
        return send_file(str(fp), as_attachment=True, download_name=fp.name)

    files = [fp for fp in (_safe_file(rel) for rel in paths) if fp]
    if not files:
        abort(404)

    # Rough zip-size estimate (ZIP_STORED means no compression, so file bytes
    # dominate) -- sent as a header so the frontend can show a real percentage
    # instead of the download going silent until the whole zip is ready.
    total_estimate = sum(fp.stat().st_size for fp in files) + len(files) * 200

    class _StreamWriter:
        """Minimal file-like object zipfile can write into -- write() hands each
        chunk to a queue that a generator drains, so bytes start reaching the
        client as each file is added instead of only after the entire zip has
        been built in memory (which used to mean the download went completely
        silent, with no feedback at all, until every file had been read)."""
        def __init__(self):
            self._q: queue.Queue = queue.Queue()
            self._pos = 0

        def write(self, b):
            b = bytes(b)
            self._pos += len(b)
            self._q.put(b)
            return len(b)

        def tell(self):
            return self._pos

        def flush(self):
            pass

    stream = _StreamWriter()

    def _build():
        try:
            with zipfile.ZipFile(stream, 'w', zipfile.ZIP_STORED, allowZip64=True) as zf:
                for fp in files:
                    zf.write(str(fp), fp.name)
        except Exception:
            pass
        finally:
            stream._q.put(None)  # sentinel: generator below stops on this

    threading.Thread(target=_build, daemon=True).start()

    def generate():
        while True:
            chunk = stream._q.get()
            if chunk is None:
                break
            yield chunk

    return Response(
        generate(),
        mimetype='application/zip',
        headers={
            'Content-Disposition': 'attachment; filename="wlm_photos.zip"',
            'X-Total-Bytes': str(total_estimate),
        }
    )


@app.route('/api/folder-counts', methods=['POST'])
def folder_counts():
    paths = (request.get_json(silent=True) or {}).get('paths', [])
    base_r = str(BASE.resolve())
    # Take a snapshot so we don't hold the lock while iterating
    with _dir_tree_mu:
        counts_snap = dict(_dir_file_counts)
    ready = _tree_ready
    results = {}
    for rel in paths[:80]:
        abs_p = str((BASE / rel).resolve())
        if not abs_p.startswith(base_r):
            continue
        prefix = abs_p + os.sep
        tp = tv = 0
        for path_str, cnt in counts_snap.items():
            if path_str == abs_p or path_str.startswith(prefix):
                tp += cnt.get('p', 0)
                tv += cnt.get('v', 0)
        # Fallback scandir only used when tree is ready (reliable direct-files check)
        if ready and tp == 0 and tv == 0:
            try:
                for entry in os.scandir(abs_p):
                    if entry.name.startswith('.') or not entry.is_file(follow_symlinks=False):
                        continue
                    ext = Path(entry.name).suffix.lower()
                    if ext in PHOTO_EXTS: tp += 1
                    elif ext in VIDEO_EXTS: tv += 1
            except OSError:
                pass
        results[rel] = {'p': tp, 'v': tv}
    return jsonify({'ready': ready, 'counts': results})


@app.route('/api/delete', methods=['POST'])
def delete_items():
    data = request.get_json(force=True) or {}
    paths = data.get('paths', [])
    is_folder = bool(data.get('folder', False))
    base_r = str(BASE.resolve())
    deleted, errors = [], []
    TRASH_DIR.mkdir(exist_ok=True)
    for rel in paths[:100]:
        try:
            abs_p = (BASE / rel).resolve()
            if not str(abs_p).startswith(base_r):
                errors.append(rel); continue
            if is_folder:
                if not abs_p.is_dir():
                    errors.append(rel); continue
            else:
                if not abs_p.is_file():
                    errors.append(rel); continue
            # Move to recycle bin instead of permanent deletion
            safe_name = f"{uuid.uuid4().hex}_{abs_p.name}"
            shutil.move(str(abs_p), str(TRASH_DIR / safe_name))
            deleted.append(rel)
        except Exception:
            errors.append(rel)
    for rel in deleted:
        try:
            abs_p = (BASE / rel).resolve()
            _invalidate_listing(abs_p if is_folder else abs_p.parent)
            _invalidate_dir_tree(abs_p if is_folder else abs_p.parent)
        except Exception:
            pass
    return jsonify({'deleted': deleted, 'errors': errors})


_TRASH_NAME_RE = re.compile(r'^[0-9a-f]{32}_(.+)$')


@app.route('/api/trash')
def api_trash():
    # Items already in .wlm_trash from a normal (recoverable) delete -- this just
    # lists what's there so it can be reviewed and, if wanted, permanently removed.
    TRASH_DIR.mkdir(exist_ok=True)
    items = []
    for entry in TRASH_DIR.iterdir():
        m = _TRASH_NAME_RE.match(entry.name)
        original_name = m.group(1) if m else entry.name
        try:
            stat = entry.stat()
            is_dir = entry.is_dir()
            if is_dir:
                size = sum(f.stat().st_size for f in entry.rglob('*') if f.is_file())
            else:
                size = stat.st_size
            items.append({
                'name': entry.name,
                'original_name': original_name,
                'is_dir': is_dir,
                'size': size,
                'deleted_at': stat.st_mtime,
                'is_media': (not is_dir) and Path(original_name).suffix.lower() in MEDIA_EXTS,
            })
        except OSError:
            continue
    items.sort(key=lambda x: -x['deleted_at'])
    return jsonify(items)


@app.route('/api/trash/delete', methods=['POST'])
def api_trash_delete():
    # Permanent, unrecoverable deletion -- items here already survived one delete
    # (they're only in .wlm_trash because of that), so this is the second and
    # final step. No soft-delete fallback: this actually removes the files.
    data = request.get_json(force=True) or {}
    names = data.get('names', [])
    trash_r = str(TRASH_DIR.resolve())
    deleted, errors = [], []
    for name in names[:200]:
        try:
            full = (TRASH_DIR / name).resolve()
            if not str(full).startswith(trash_r) or full == TRASH_DIR.resolve():
                errors.append(name); continue
            if full.is_dir():
                shutil.rmtree(full)
            elif full.is_file():
                full.unlink()
            else:
                errors.append(name); continue
            deleted.append(name)
        except Exception:
            errors.append(name)
    return jsonify({'deleted': deleted, 'errors': errors})


@app.route('/api/mkdir', methods=['POST'])
def mkdir_folders():
    data = request.get_json(force=True) or {}
    parent_rel = data.get('parent', '')
    names = data.get('names', [])
    if not parent_rel or not names:
        abort(400)
    base_r = str(BASE.resolve())
    parent_abs = (BASE / parent_rel).resolve()
    if not str(parent_abs).startswith(base_r) or not parent_abs.is_dir():
        abort(400)
    # Match ownership of parent so Finder/File Station can manage created folders
    try:
        p_stat = parent_abs.stat()
        p_uid, p_gid = p_stat.st_uid, p_stat.st_gid
    except OSError:
        p_uid, p_gid = -1, -1
    created, errors = [], []
    for name in names[:50]:
        name = name.strip()
        if not name or '/' in name or name.startswith('.'):
            errors.append(name); continue
        try:
            new_dir = parent_abs / name
            new_dir.mkdir(exist_ok=False)
            try: os.chmod(str(new_dir), 0o777)
            except OSError: pass
            if p_uid >= 0:
                try: os.chown(str(new_dir), p_uid, p_gid)
                except OSError: pass
            created.append(name)
        except FileExistsError:
            errors.append(name)
        except Exception:
            errors.append(name)
    if created:
        _invalidate_listing(parent_abs)
        _invalidate_dir_tree(parent_abs)
    return jsonify({'created': created, 'errors': errors})


def _own_like_parent(path, p_uid, p_gid):
    # New dirs/files created here inherit the container's root ownership, and
    # on this NAS a directory freshly created by root -- with no ACL entry
    # matching root -- silently ends up mode 000 (Synology/QNAP ACL quirk):
    # the copy "succeeds" but the folder is completely impassable, which is
    # exactly what looked like "the files didn't copy over". Force it open and
    # match the parent's ownership, same as /api/mkdir already does.
    try:
        os.chmod(str(path), 0o777)
    except OSError:
        pass
    if p_uid >= 0:
        try:
            os.chown(str(path), p_uid, p_gid)
        except OSError:
            pass


def _copy_folder_worker(job_id: str, src_rel: str, dest_rel: str, include_files: bool):
    src_abs  = (BASE / src_rel).resolve()
    dest_abs = (BASE / dest_rel).resolve()
    target = dest_abs / src_abs.name
    try:
        p_uid, p_gid = -1, -1
        try:
            d_stat = dest_abs.stat()
            p_uid, p_gid = d_stat.st_uid, d_stat.st_gid
        except OSError:
            pass
        if include_files:
            files = []
            for root, dirs, filenames in os.walk(str(src_abs)):
                dirs[:] = [d for d in dirs if not d.startswith('.') and d not in _SKIP_DIRS]
                for f in filenames:
                    if not f.startswith('.'):
                        files.append(Path(root) / f)
            with _copy_jobs_mu:
                _copy_jobs[job_id]['total'] = len(files)
            made_dirs = set()
            for i, fp in enumerate(files):
                dst_fp = target / fp.relative_to(src_abs)
                if dst_fp.parent not in made_dirs:
                    dst_fp.parent.mkdir(parents=True, exist_ok=True)
                    d = dst_fp.parent
                    while d not in made_dirs:
                        _own_like_parent(d, p_uid, p_gid)
                        made_dirs.add(d)
                        if d == target:
                            break
                        d = d.parent
                shutil.copy2(str(fp), str(dst_fp))
                _own_like_parent(dst_fp, p_uid, p_gid)
                with _copy_jobs_mu:
                    _copy_jobs[job_id]['done'] = i + 1
        else:
            dirs_list = []
            for root, dirs, _ in os.walk(str(src_abs)):
                dirs[:] = [d for d in dirs if not d.startswith('.') and d not in _SKIP_DIRS]
                dirs_list.append(Path(root))
            with _copy_jobs_mu:
                _copy_jobs[job_id]['total'] = len(dirs_list)
            for i, root_path in enumerate(dirs_list):
                d = target / root_path.relative_to(src_abs)
                d.mkdir(parents=True, exist_ok=True)
                _own_like_parent(d, p_uid, p_gid)
                with _copy_jobs_mu:
                    _copy_jobs[job_id]['done'] = i + 1
        _invalidate_listing(dest_abs)
        _invalidate_dir_tree(dest_abs)
        with _copy_jobs_mu:
            _copy_jobs[job_id]['finished'] = True
    except Exception as ex:
        with _copy_jobs_mu:
            _copy_jobs[job_id]['finished'] = True
            _copy_jobs[job_id]['error'] = str(ex)


@app.route('/api/copy-folder', methods=['POST'])
def copy_folder():
    data = request.get_json(force=True) or {}
    src_rel  = data.get('src', '')
    dest_rel = data.get('dest', '')
    include_files = bool(data.get('include_files', False))
    if not src_rel or not dest_rel:
        return jsonify({'ok': False, 'error': 'missing src or dest'}), 400
    base_r = str(BASE.resolve())
    src_abs  = (BASE / src_rel).resolve()
    dest_abs = (BASE / dest_rel).resolve()
    if not str(src_abs).startswith(base_r) or not str(dest_abs).startswith(base_r):
        return jsonify({'ok': False, 'error': 'path outside base'}), 400
    if not src_abs.is_dir() or not dest_abs.is_dir():
        return jsonify({'ok': False, 'error': 'src or dest not a directory'}), 400
    job_id = uuid.uuid4().hex[:8]
    with _copy_jobs_mu:
        _copy_jobs[job_id] = {
            'done': 0, 'total': 0, 'finished': False, 'error': None,
            'src': src_rel, 'dest': dest_rel, 'name': src_abs.name,
        }
    threading.Thread(target=_copy_folder_worker, args=(job_id, src_rel, dest_rel, include_files), daemon=True).start()
    return jsonify({'ok': True, 'job_id': job_id})


def _copy_files_worker(job_id: str, srcs: list, dest_abs):
    try:
        p_uid, p_gid = -1, -1
        try:
            d_stat = dest_abs.stat()
            p_uid, p_gid = d_stat.st_uid, d_stat.st_gid
        except OSError:
            pass
        for i, fp in enumerate(srcs):
            dst_fp = dest_abs / fp.name
            shutil.copy2(str(fp), str(dst_fp))
            _own_like_parent(dst_fp, p_uid, p_gid)
            with _copy_jobs_mu:
                _copy_jobs[job_id]['done'] = i + 1
        _invalidate_listing(dest_abs)
        _invalidate_dir_tree(dest_abs)
        with _copy_jobs_mu:
            _copy_jobs[job_id]['finished'] = True
    except Exception as ex:
        with _copy_jobs_mu:
            _copy_jobs[job_id]['finished'] = True
            _copy_jobs[job_id]['error'] = str(ex)


@app.route('/api/copy-files', methods=['POST'])
def copy_files():
    """Copies an explicit list of individual files (e.g. a grid selection) into a
    destination folder -- unlike /api/copy-folder, this ignores directory
    structure entirely and drops every file flat into dest. Shares the same
    _copy_jobs polling mechanism and the same permission fix as copy-folder."""
    data = request.get_json(force=True) or {}
    paths = data.get('paths', [])
    dest_rel = data.get('dest', '')
    if not paths or not dest_rel:
        return jsonify({'ok': False, 'error': 'missing paths or dest'}), 400
    base_r = str(BASE.resolve())
    dest_abs = (BASE / dest_rel).resolve()
    if not str(dest_abs).startswith(base_r) or not dest_abs.is_dir():
        return jsonify({'ok': False, 'error': 'dest not a directory'}), 400
    srcs = []
    for rel in paths:
        full = (BASE / rel).resolve()
        if str(full).startswith(base_r) and full.is_file():
            srcs.append(full)
    if not srcs:
        return jsonify({'ok': False, 'error': 'no valid files'}), 400
    job_id = uuid.uuid4().hex[:8]
    with _copy_jobs_mu:
        _copy_jobs[job_id] = {
            'done': 0, 'total': len(srcs), 'finished': False, 'error': None,
            'src': f'{len(srcs)} file(s)', 'dest': dest_rel, 'name': f'{len(srcs)} file(s)',
        }
    threading.Thread(target=_copy_files_worker, args=(job_id, srcs, dest_abs), daemon=True).start()
    return jsonify({'ok': True, 'job_id': job_id})


@app.route('/api/copy-job/<job_id>')
def api_copy_job(job_id):
    with _copy_jobs_mu:
        if job_id not in _copy_jobs:
            abort(404)
        return jsonify(dict(_copy_jobs[job_id]))


@app.route('/api/move-folder', methods=['POST'])
def move_folder():
    """Relocates a whole folder to a different parent (drag-and-drop in the
    sidebar tree) -- distinct from /api/rename, which only changes the last
    path segment in place. A plain rename() (not a copy) so the moved folder
    keeps its existing ownership/permissions -- none of the /api/copy-folder
    ACL quirk applies here since nothing new is being created."""
    data = request.get_json(force=True) or {}
    src_rel  = data.get('src', '').strip('/')
    dest_rel = data.get('dest', '').strip('/')
    if not src_rel:
        return jsonify({'ok': False, 'error': 'missing src'}), 400
    base_r = str(BASE.resolve())
    src_abs  = (BASE / src_rel).resolve()
    dest_abs = (BASE / dest_rel).resolve()
    if not str(src_abs).startswith(base_r) or not src_abs.is_dir():
        return jsonify({'ok': False, 'error': 'source folder not found'}), 404
    if not str(dest_abs).startswith(base_r) or not dest_abs.is_dir():
        return jsonify({'ok': False, 'error': 'destination folder not found'}), 404
    if dest_abs == src_abs or str(dest_abs).startswith(str(src_abs) + os.sep):
        return jsonify({'ok': False, 'error': "Can't move a folder into itself"}), 400
    if dest_abs == src_abs.parent:
        return jsonify({'ok': False, 'error': 'Already in that folder'}), 400
    new_abs = dest_abs / src_abs.name
    if new_abs.exists():
        return jsonify({'ok': False, 'error': f'"{src_abs.name}" already exists in the destination'}), 409
    old_parent = src_abs.parent
    try:
        src_abs.rename(new_abs)
    except OSError as exc:
        return jsonify({'ok': False, 'error': str(exc)}), 500
    _invalidate_listing(old_parent)
    _invalidate_dir_tree(old_parent)
    _invalidate_listing(dest_abs)
    _invalidate_dir_tree(dest_abs)
    new_rel = str(new_abs.relative_to(BASE.resolve()))
    return jsonify({'ok': True, 'new_path': new_rel})


@app.route('/api/rename', methods=['POST'])
def rename_folder():
    data = request.get_json(force=True) or {}
    rel_path = data.get('path', '').strip('/')
    new_name = data.get('name', '').strip()
    if not rel_path or not new_name or '/' in new_name or new_name.startswith('.'):
        return jsonify({'error': 'Invalid path or name'}), 400
    base_r = str(BASE.resolve())
    old_abs = (BASE / rel_path).resolve()
    if not str(old_abs).startswith(base_r) or not old_abs.exists():
        return jsonify({'error': 'Folder not found'}), 404
    parent_abs = old_abs.parent
    new_abs = parent_abs / new_name
    if new_abs.exists():
        return jsonify({'error': f'"{new_name}" already exists'}), 409
    parent_rel = str(parent_abs.relative_to(BASE.resolve()))
    new_rel = (parent_rel + '/' + new_name).lstrip('/')
    try:
        old_abs.rename(new_abs)
    except OSError as exc:
        return jsonify({'error': str(exc)}), 500
    _invalidate_listing(parent_abs)
    _invalidate_dir_tree(parent_abs)
    return jsonify({'new_path': new_rel, 'new_name': new_name})


@app.route('/api/rate', methods=['POST'])
def rate_photos():
    data = request.get_json()
    paths  = data.get('paths', [])
    rating = data.get('rating')   # int 0-5 or None (don't change)
    flag   = data.get('flag')     # 'pick'|'reject'|'none' or None (don't change)
    if not paths or (rating is None and flag is None):
        return jsonify({'ok': False}), 400

    from collections import defaultdict
    by_folder: dict[str, list] = defaultdict(list)
    for rel in paths:
        p = BASE / rel
        if p.is_file():
            by_folder[str(p.parent)].append((rel, p.name))

    for folder_str, items in by_folder.items():
        folder_path = Path(folder_str)
        rfile = folder_path / '.wlm_ratings.json'
        try:
            ratings = json.loads(rfile.read_text()) if rfile.is_file() else {}
        except Exception:
            ratings = {}
        for _rel, name in items:
            entry = dict(ratings.get(name, {}))
            if rating is not None:
                entry['rating'] = rating
            if flag is not None:
                entry['flag'] = flag
            ratings[name] = entry
        try:
            rfile.write_text(json.dumps(ratings))
        except Exception:
            pass
        # Invalidate listing cache for any folder that contains this path
        for key in list(_listing_cache):
            if folder_str.startswith(key) or key.startswith(folder_str):
                _listing_cache.pop(key, None)

    return jsonify({'ok': True})


@app.route('/api/list-cached-files/<path:folder>')
def list_cached_files(folder):
    """Return every filename that has a thumbnail under the given folder path, with sizes."""
    thumb_folder = THUMB_DIR / folder
    if not thumb_folder.exists():
        return jsonify({'error': 'No thumbnails cached for this path', 'files': []})
    result = {}
    sizes = {}
    for root, dirs, files in os.walk(str(thumb_folder)):
        dirs[:] = sorted((d for d in dirs if not d.startswith('.')), key=_nat)
        root_path = Path(root)
        rel_dir = str(root_path.relative_to(thumb_folder))
        jpgs = sorted(
            (f for f in files if f.endswith('.jpg') and not f.startswith('.')),
            key=_nat
        )
        if jpgs:
            names = [f[:-4] for f in jpgs]
            result[rel_dir] = names
            size_map = {}
            for f, name in zip(jpgs, names):
                try:
                    size_map[name] = (root_path / f).stat().st_size
                except OSError:
                    pass
            sizes[rel_dir] = size_map
    return jsonify({'folder': folder, 'subfolder_files': result, 'subfolder_sizes': sizes})


# ── Startup ───────────────────────────────────────────────────────────────────

def _init():
    THUMB_DIR.mkdir(parents=True, exist_ok=True)
    _cleanup_expired_caches()
    threading.Thread(target=_watcher_loop, daemon=True).start()
    threading.Thread(target=_dir_tree_loop, daemon=True).start()

threading.Thread(target=_init, daemon=True).start()


# macOS's standalone Tailscale.app doesn't always put its CLI on PATH unless
# the client turns that on manually (menu bar app -> "Install Tailscale
# command line tool"). Fall back to its known install locations so a client
# who just installed the app normally doesn't spin in the retry loop forever.
_TAILSCALE_FALLBACK_PATHS = [
    '/usr/local/bin/tailscale',
    '/opt/homebrew/bin/tailscale',
    '/Applications/Tailscale.app/Contents/MacOS/Tailscale',
]


def _tailscale_binary():
    if shutil.which('tailscale'):
        return 'tailscale'
    for p in _TAILSCALE_FALLBACK_PATHS:
        if Path(p).exists():
            return p
    return 'tailscale'


def _tailscale_ip_is_live(ip: str) -> bool:
    """`tailscale ip -4` keeps returning the last-known address (exit code 0,
    no error) even after Tailscale has been stopped/disconnected — it's
    reporting the tailnet identity, not current connectivity. Cross-check
    against the machine's actual network interfaces so a stopped Tailscale
    doesn't get treated as connected, which would otherwise bind to a dead
    address and fail with "Can't assign requested address"."""
    try:
        for addrs in psutil.net_if_addrs().values():
            for addr in addrs:
                if addr.address == ip:
                    return True
    except Exception:
        pass
    return False


def _get_tailscale_ip(retry_interval=5):
    """Block until Tailscale is actually connected with a live address, then
    return it.

    This is a client-facing build: the server must never be reachable except
    over Tailscale, so we retry forever rather than falling back to
    0.0.0.0/localhost if Tailscale isn't up yet at launch.
    """
    while True:
        try:
            result = subprocess.run(
                [_tailscale_binary(), 'ip', '-4'],
                capture_output=True, text=True, timeout=5,
            )
            lines = result.stdout.strip().splitlines()
            if result.returncode == 0 and lines and _tailscale_ip_is_live(lines[0]):
                return lines[0]
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        print(f"[startup] Waiting for Tailscale to come up (retrying in {retry_interval}s)...", flush=True)
        time.sleep(retry_interval)


def _get_tailscale_hostname():
    """This device's MagicDNS name (e.g. foo.tailxxxx.ts.net), trailing dot
    stripped. HTTPS certs are issued for hostnames, not raw IPs — a browser
    can't validate a certificate against an IP address at all."""
    try:
        result = subprocess.run(
            [_tailscale_binary(), 'status', '--json'],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            data = json.loads(result.stdout)
            dns_name = data.get('Self', {}).get('DNSName', '')
            if dns_name:
                return dns_name.rstrip('.')
    except Exception:
        pass
    return None


_TLS_CERT_DIR = Path(os.environ.get('TLS_CERT_DIR', str(Path.home() / '.wlm_sorting_tls')))


def _get_tailscale_https_cert(hostname):
    """Runs `tailscale cert` for this hostname; returns (certfile, keyfile) on
    success or None. Safe and cheap to call on every startup instead of
    tracking expiry ourselves — Tailscale's own cert command is idempotent
    and only does real work when a renewal is actually needed. Fails (returns
    None) until the client has turned on "HTTPS Certificates" for their
    Tailscale account — a one-time setting, not something on our side."""
    try:
        _TLS_CERT_DIR.mkdir(parents=True, exist_ok=True)
        certfile = _TLS_CERT_DIR / f'{hostname}.crt'
        keyfile = _TLS_CERT_DIR / f'{hostname}.key'
        result = subprocess.run(
            [_tailscale_binary(), 'cert', f'--cert-file={certfile}', f'--key-file={keyfile}', hostname],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0 and certfile.exists() and keyfile.exists():
            return str(certfile), str(keyfile)
    except Exception:
        pass
    return None


def _get_tailscale_https_info(retry_interval=5):
    """Blocks until Tailscale is connected AND an HTTPS cert is available for
    it. Returns (bind_ip, hostname, certfile, keyfile)."""
    bind_ip = _get_tailscale_ip(retry_interval)  # blocks on its own until genuinely connected
    while True:
        hostname = _get_tailscale_hostname()
        if not hostname:
            print(f"[startup] Waiting for Tailscale hostname (retrying in {retry_interval}s)...", flush=True)
            time.sleep(retry_interval)
            continue
        cert = _get_tailscale_https_cert(hostname)
        if not cert:
            print(
                f"[startup] Waiting for HTTPS Certificates to be enabled on this Tailscale "
                f"account (retrying in {retry_interval}s)... Enable it at "
                f"https://login.tailscale.com/admin/dns", flush=True,
            )
            time.sleep(retry_interval)
            continue
        certfile, keyfile = cert
        return bind_ip, hostname, certfile, keyfile


if __name__ == '__main__':
    bind_host, hostname, certfile, keyfile = _get_tailscale_https_info()
    print(f"[startup] Binding to https://{hostname}:{os.environ.get('PORT', 5000)} only — not reachable via localhost or LAN.", flush=True)
    app.run(
        host=bind_host, port=int(os.environ.get('PORT', 5000)), threaded=True,
        use_reloader=False, ssl_context=(certfile, keyfile),
    )
