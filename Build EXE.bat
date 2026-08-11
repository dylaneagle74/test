@echo off
setlocal
cd /d "%~dp0"
py -3 -m pip install -r requirements.txt || exit /b 1
if not exist "patches\oot-vc-usa-h63.ips" (
  echo.
  echo H63 patch payload is missing.
  echo Run OoTVCFixPatcher.py and use Maintainer ^> Build H63 patch payload first.
  echo.
  pause
  exit /b 2
)
py -3 -m PyInstaller --noconfirm --clean --onefile --windowed ^
  --name OoTVCFixPatcher-H63 ^
  --add-data "patches\oot-vc-usa-h63.ips;patches" ^
  --hidden-import Crypto.Cipher.AES ^
  OoTVCFixPatcher.py
if errorlevel 1 exit /b %errorlevel%
echo.
echo Built: dist\OoTVCFixPatcher-H63.exe
pause
