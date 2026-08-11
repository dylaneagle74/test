@echo off
setlocal
cd /d "%~dp0"

echo ============================================================
echo Ocarina of Time Wii VC Fix Patcher H63 - Windows EXE Builder
echo ============================================================
echo.

echo Installing/updating build dependencies...
py -3 -m pip install -r requirements.txt || goto :error

echo.
echo Verifying the bundled H63 IPS payload...
py -3 OoTVCFixPatcher.py --verify-payload || goto :error

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
echo.
echo End users only need that EXE and their own original NACE WAD.
echo No H63 reference WAD is required.
echo ============================================================
echo.
pause
exit /b 0

:error
echo.
echo ERROR: Build failed. Review the message above.
echo.
pause
exit /b 1
