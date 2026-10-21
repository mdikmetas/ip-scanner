@echo off
REM IP Tarayici - Windows .exe olusturucu
REM Gereksinim: Python 3 kurulu olmali (python.org, "Add to PATH" isaretli)
REM ip_scanner.py ile ayni klasorde calistirin.

python -m pip install --upgrade pyinstaller
python -m PyInstaller --noconfirm --onefile --windowed --name "IP Tarayici" ip_scanner.py

echo.
echo Bitti: dist\IP Tarayici.exe
pause
