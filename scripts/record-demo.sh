#!/usr/bin/env bash
# Record Beats 1–4 of the Taint-Flow Auditor demo to an mp4.
#
# How it works:
#   1. Starts ffmpeg capturing the whole main display (avfoundation index 1).
#   2. Runs scripts/run-demo.sh in this same terminal so its output is visible.
#   3. Stops ffmpeg cleanly on exit.
#
# Prereqs (one-time):
#   * Run this from Terminal.app (not VS Code's terminal). Make the window
#     large and put it in front — ffmpeg captures whatever is on screen.
#   * First run: macOS will prompt to grant Screen Recording to Terminal.
#     Accept, then re-run.
#
# Output: /tmp/taint-demo.mp4
set -e

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="/tmp/taint-demo.mp4"
[ -f "$OUT" ] && rm -f "$OUT"

# avfoundation video index 1 = "Capture screen 0" (main display)
# -framerate 30, H.264 hardware-encoded, no audio (-an).
# -y overwrites silently.
ffmpeg -hide_banner -loglevel warning \
  -f avfoundation -framerate 30 -capture_cursor 1 -i "1:none" \
  -c:v h264_videotoolbox -b:v 6M -pix_fmt yuv420p \
  -y "$OUT" &
FFMPEG_PID=$!

# Give the encoder a beat to start, otherwise the title flashes by.
sleep 2

cleanup() {
  # SIGINT lets ffmpeg flush the moov atom (mp4 plays in any editor)
  kill -INT "$FFMPEG_PID" 2>/dev/null || true
  wait "$FFMPEG_PID" 2>/dev/null || true
  echo
  echo "Recording saved to: $OUT"
  ls -lh "$OUT"
}
trap cleanup EXIT

bash "$REPO_ROOT/scripts/run-demo.sh"
