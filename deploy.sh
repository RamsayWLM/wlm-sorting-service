#!/bin/bash
set -e

NAS_HOST="admin@192.168.1.2"
NAS_DIR="/volume1/Public/wlm-viewer-v2"
LOCAL_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "→ Pushing app.py..."
scp "$LOCAL_DIR/app.py" "$NAS_HOST:$NAS_DIR/app.py"

echo "→ Pushing index.html..."
scp "$LOCAL_DIR/templates/index.html" "$NAS_HOST:$NAS_DIR/templates/index.html"

if [[ "$1" == "--restart" ]]; then
  echo "→ Restarting container..."
  ssh "$NAS_HOST" "cd '$NAS_DIR' && docker-compose restart"
  echo "✓ Done — container restarted"
else
  echo "✓ Done — Flask reloader picks up app.py in ~1s"
  echo "  Hard refresh browser (⌘+Shift+R) to see HTML changes"
fi
