@echo off

REM Function to check Python version and set global variable
CALL :checkPythonVersion
IF "%PYTHON_CMD%"=="" (
    echo Python 3.8 or higher is required.
    exit /b 1
)
GOTO :main

:checkPythonVersion
python -c "import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1);" >nul 2>&1
IF %ERRORLEVEL% == 0 SET PYTHON_CMD=python & GOTO :EOF
python3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1);" >nul 2>&1
IF %ERRORLEVEL% == 0 SET PYTHON_CMD=python3 & GOTO :EOF
SET PYTHON_CMD=
GOTO :EOF

:main
REM Check if the virtual environment already exists
IF NOT EXIST "venv" (
    REM Create python virtual environment
    %PYTHON_CMD% -m venv .\venv

    REM Activate venv
    .\venv\Scripts\activate.bat

    REM Install requirements
    pip install -r requirements.txt

    REM Install capstone
    pip install capstone
    REM Run
	%PYTHON_CMD% .\main.py
) ELSE (
    REM Activate venv
    .\venv\Scripts\activate.bat
    REM Run
	%PYTHON_CMD% .\main.py
)