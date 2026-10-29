#!/usr/bin/env bash
# Take README screenshots with headless Chrome against the synthetic demo.
# Usage: scripts/screenshot.sh   (needs google-chrome or chromium on PATH)
set -euo pipefail
cd "$(dirname "$0")/.."
CHROME=${CHROME:-$(command -v google-chrome || command -v chromium || command -v chromium-browser)}
python3 scripts/demo.py > /tmp/wiretap-demo.log 2>&1 &
PID=$!; trap "kill $PID 2>/dev/null" EXIT
for i in $(seq 1 50); do curl -sf http://127.0.0.1:8788/api/info >/dev/null && grep -q "sent 3" /tmp/wiretap-demo.log && break; sleep 0.2; done
kill -0 $PID 2>/dev/null || { echo "demo failed to start (ports 8787/8788 busy?):"; cat /tmp/wiretap-demo.log; exit 1; }
sleep 1
shot(){ "$CHROME" --headless=new --no-sandbox --disable-gpu --hide-scrollbars --window-size=1440,900 \
  --virtual-time-budget=4000 --screenshot="docs/$1" "http://127.0.0.1:8788/#$2" 2>/dev/null; echo "wrote docs/$1"; }
shot screenshot-overview.png "id=3&tab=overview&theme=light"
shot screenshot-tools.png "id=3&tab=tools&theme=light"
shot screenshot-diff.png "id=2&tab=diff&theme=light"
shot screenshot-pii.png "id=3&tab=pii&theme=light"
shot screenshot-system.png "id=3&tab=system&theme=light"
shot screenshot-hidden.png "id=3&tab=hidden&theme=light"
shot screenshot-overview-dark.png "id=3&tab=overview&theme=dark"
shot screenshot-hidden-dark.png "id=3&tab=hidden&theme=dark"
shot screenshot-pii-dark.png "id=3&tab=pii&theme=dark"
