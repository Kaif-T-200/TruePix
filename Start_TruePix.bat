@echo off
setlocal
cd /d "%~dp0"

REM --- Choose Python: prefer a local .venv if it exists ---
if exist ".venv\Scripts\python.exe" (
    set "PY=.venv\Scripts\python.exe"
) else (
    set "PY=python"
)

REM --- Install requirements only if streamlit is not importable ---
"%PY%" -c "import streamlit" >nul 2>&1
if errorlevel 1 (
    echo [TruePix] Dependencies missing - installing now, this may take a minute...
    "%PY%" -m pip install -r requirements.txt
)

REM --- Find a free port starting at 8501 ---
for /f "usebackq delims=" %%p in (`"%PY%" find_port.py`) do set "PORT=%%p"

echo [TruePix] Launching on http://localhost:%PORT%
echo [TruePix] Close this window to stop TruePix.

REM Open the browser shortly after startup (minimized helper window).
start "" /min powershell -NoProfile -Command "Start-Sleep -Seconds 4; Start-Process 'http://localhost:%PORT%'"

REM Run Streamlit in the FOREGROUND so it is a child of this console.
REM Closing the window sends the close signal to this process tree and
REM terminates Streamlit, releasing the port.
"%PY%" -m streamlit run app.py --server.headless=true --server.port=%PORT% --server.address=localhost

endlocal
