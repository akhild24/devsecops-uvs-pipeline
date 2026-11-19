@echo off
setlocal
echo ============================================================
echo   DevSecOps UVS Pipeline - one-click setup
echo ============================================================
echo.
echo This window will install everything and start the project.
echo It can take a few minutes the first time. Please wait.
echo.

cd /d "%~dp0backend"
echo [1/4] Installing backend requirements...
python -m pip install -r requirements.txt
if errorlevel 1 (
    echo.
    echo Something went wrong installing Python packages.
    echo Copy the red error text above and send it back for help.
    pause
    exit /b 1
)

echo.
echo [2/4] Starting the backend in a new window...
start "DevSecOps Backend" /D "%~dp0backend" cmd /k "uvicorn main:app --reload"

echo.
echo Loading the sample commits for the dashboard...
cd /d "%~dp0backend"
python scripts\post_samples.py
if errorlevel 1 (
    echo.
    echo The backend did not start or the sample data could not be loaded.
    echo Check the DevSecOps Backend window for the error.
    pause
    exit /b 1
)

cd /d "%~dp0frontend"
echo.
echo [3/4] Installing dashboard requirements (this is the slow one, be patient)...
call npm install
if errorlevel 1 (
    echo.
    echo Something went wrong installing the dashboard packages.
    echo Copy the red error text above and send it back for help.
    pause
    exit /b 1
)

echo.
echo [4/4] Starting the dashboard in a new window...
start "DevSecOps Dashboard" /D "%~dp0frontend" cmd /k "npm run dev"

echo.
echo ============================================================
echo   Almost done. Two new black windows just opened - leave
echo   them both running. Wait about 10 seconds, then open your
echo   browser and go to:
echo.
echo       http://localhost:5173
echo.
echo   To test that it's working, also try:
echo       http://localhost:8000/docs
echo ============================================================
echo.
pause
