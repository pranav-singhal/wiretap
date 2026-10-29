#!/usr/bin/env bash
# Record docs/demo-synthetic.gif + docs/demo-synthetic.mp4 from the wiretap UI using SYNTHETIC demo traffic only.
# Needs: google-chrome (or $CHROME), node >= 20, ffmpeg.   Usage: scripts/record_gif.sh
set -euo pipefail
cd "$(dirname "$0")/.."
FRAMES=${FRAMES:-/tmp/wiretap-frames}; FPS=${FPS:-15}; GIF_W=${GIF_W:-1200}
python3 scripts/demo.py > /tmp/wiretap-demo.log 2>&1 &
PID=$!; trap "kill $PID 2>/dev/null" EXIT
for i in $(seq 1 50); do curl -sf http://127.0.0.1:8788/api/info >/dev/null && grep -q "sent 3" /tmp/wiretap-demo.log && break; sleep 0.2; done
kill -0 $PID 2>/dev/null || { echo "demo failed to start (ports 8787/8788 busy?):"; cat /tmp/wiretap-demo.log; exit 1; }
NODE_FLAGS=""; node -e 'process.exit(typeof WebSocket==="function"?0:1)' || NODE_FLAGS="--experimental-websocket"
FRAMES=$FRAMES FPS=$FPS node $NODE_FLAGS --no-warnings scripts/record_gif.mjs
# GIF: one palette for the whole clip, only changed pixels re-encoded per frame
ffmpeg -y -loglevel error -framerate "$FPS" -i "$FRAMES/f%05d.png" \
  -vf "scale=$GIF_W:-1:flags=lanczos,split[a][b];[a]palettegen=max_colors=128:stats_mode=diff[p];[b][p]paletteuse=dither=bayer:bayer_scale=5:diff_mode=rectangle" \
  -loop 0 docs/demo-synthetic.gif
# MP4: smaller and sharper, for places that accept video (X, GitHub drag-and-drop)
ffmpeg -y -loglevel error -framerate "$FPS" -i "$FRAMES/f%05d.png" \
  -c:v libx264 -pix_fmt yuv420p -crf 24 -preset slow -movflags +faststart docs/demo-synthetic.mp4
ls -lh docs/demo-synthetic.gif docs/demo-synthetic.mp4
