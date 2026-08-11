@echo off
setlocal
cd /d "%~dp0"

echo Installing/updating build dependencies...
py -3 -m pip install -r requirements.txt || goto :error

if not exist "patches\oot-vc-usa-h63.ips" (
  echo.
  echo H63 patch payload has not been generated yet.
  echo Two file pickers will open:
  echo   1. your exact original USA/NACE OoT VC WAD
  echo   2. the tested H63 reference WAD
  echo.
  py -3 OoTVCFixPatcher.py --build-payload
  if errorlevel 1 goto :payload_error
)

if not exist "patches\oot-vc-usa-h63.ips" goto :payload_error

echo.
echo Building standalone Windows GUI patcher...
py -3 -m PyInstaller --noconfirm --clean --onefile --windowed ^
  --name OoTVCFixPatcher-H63 ^
  --add-data "patches\oot-vc-usa-h63.ips;patches" ^
  --hidden-import Crypto.Cipher.AES ^
  OoTVCFixPatcher.py
if errorlevel 1 goto :error

echo.
echo ============================================================
echo SUCCESS
echo Built: dist\OoTVCFixPatcher-H63.exe
echo ============================================================
echo.
pause
exit /b 0

:payload_error
echo.
echo ERROR: H63 payload generation was cancelled or failed.
echo The EXE was not built.
echo.
pause
exit /b 2

:error
echo.
echo ERROR: Build failed. Review the message above.
echo.
pause
exit /b 1
