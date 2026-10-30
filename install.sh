#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
BIN="$HOME/.local/bin"
APP="$HOME/.local/share/advanced-privacy-defense"
CONF="$HOME/.config/advanced-privacy-defense"

if ! command -v python3 >/dev/null 2>&1; then
  echo "Python 3 belum terpasang." >&2
  exit 1
fi

echo "[1/4] Memeriksa dependensi..."
if command -v apt-get >/dev/null 2>&1; then
  sudo apt-get update
  sudo apt-get install -y python3 python3-tk curl tor wireguard-tools nftables iproute2
elif command -v pacman >/dev/null 2>&1; then
  sudo pacman -Sy --needed python tk curl tor wireguard-tools nftables iproute2
elif command -v dnf >/dev/null 2>&1; then
  sudo dnf install -y python3 python3-tkinter curl tor wireguard-tools nftables iproute
else
  echo "Package manager tidak dikenali; pastikan Python 3, Tkinter, dan curl tersedia."
fi

echo "[2/4] Memasang source..."
install -d -m 700 "$APP" "$CONF"
install -m 700 "$ROOT/pps.py" "$APP/pps.py"
install -d "$BIN"
printf '#!/usr/bin/env bash\nexec python3 "%s/pps.py" "$@"\n' "$APP" > "$BIN/pps"
chmod 755 "$BIN/pps"

echo "[3/4] Menyiapkan konfigurasi..."
if [[ ! -f "$CONF/config.json" ]]; then
  cat > "$CONF/config.json" <<'JSON'
{
  "proxy": "socks5h://127.0.0.1:9050",
  "mode": "balanced",
  "scope": "both"
}
JSON
  chmod 600 "$CONF/config.json"
fi

echo "[4/4] Menjalankan pemeriksaan lokal..."
python3 "$APP/pps.py" self-test
python3 -m py_compile "$APP/pps.py"

echo
echo "Instalasi selesai."
echo "Jalankan: export PATH=\"$HOME/.local/bin:$PATH\""
echo "Lalu: pps status"
echo "GUI: pps gui"
echo "Tor tidak otomatis dijalankan; aktifkan jika diinginkan:"
echo "sudo systemctl enable --now tor"
