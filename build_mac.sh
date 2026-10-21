#!/bin/bash
# IP Tarayici - macOS .app olusturucu
# Gereksinim: python3 (tkinter dahil; python.org surumu onerilir)
# ip_scanner.py ile ayni klasorde calistirin:  bash build_mac.sh
set -e
cd "$(dirname "$0")"

python3 -m pip install --upgrade pyinstaller
python3 -m PyInstaller --noconfirm --windowed --name "IP Tarayici" ip_scanner.py

echo
echo "Bitti: dist/IP Tarayici.app"
echo "Ilk acilista: sag tik > Ac (imzasiz uygulama uyarisi icin)"
