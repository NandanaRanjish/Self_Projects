#!/usr/bin/env bash
# Single ESP32-S3 merged firmware image. FLASHES BOOTLOADER + PARTITION + APP.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
PORT=${1:-/dev/ttyACM0}
IMAGE="$ROOT/firmware/MAARS_ESP32S3_Unified.bin"
[[ -f "$IMAGE" ]] || { echo "Missing firmware image" >&2;exit 2; }
echo "ESP32-S3 ONLY: about to overwrite flash regions including bootloader/partitions."

echo "Port: $PORT"; echo "Firmware: $IMAGE"
read -r -p "Type FLASH to continue: " CONFIRM
[[ "$CONFIRM" == FLASH ]] || { echo "Cancelled";exit 1; }
PYTHON=${PY:-python3}
"$PYTHON" -m esptool --chip esp32s3 --port "$PORT" --baud 460800 write_flash 0x0 "$IMAGE"
echo "Flashed merged image."
