@echo off
echo ================================================
echo  📁 Organizing Malicious URL Detector Project
echo ================================================

REM Create main project directories if they don't exist
if not exist "data" mkdir data
if not exist "docs" mkdir docs
if not exist "scripts" mkdir scripts
if not exist "logs" mkdir logs

echo ✅ Created directory structure

REM Move Python files to appropriate locations
echo 📄 Organizing Python files...
if exist "url_detector.py" (
    echo    ✓ url_detector.py already in root
) else (
    if exist "malicious_url_detector.py" move "malicious_url_detector.py" "url_detector.py"
    if exist "detector.py" move "detector.py" "url_detector.py"
    if exist "main.py" move "main.py" "url_detector.py"
)

REM Move data files to data folder
echo 📊 Organizing data files...
if exist "*.csv" (
    for %%f in (*.csv) do (
        if /i "%%f" neq "maliciouslinks.csv" (
            move "%%f" "data\"
            echo    ✓ Moved %%f to data/
        )
    )
)

if exist "training_data.csv" move "training_data.csv" "data\"
if exist "dataset.csv" move "dataset.csv" "data\"
if exist "urls.csv" move "urls.csv" "data\"
if exist "*.xlsx" move "*.xlsx" "data\"
if exist "*.json" move "*.json" "data\"

REM Move documentation files
echo 📚 Organizing documentation...
if exist "*.md" (
    for %%f in (*.md) do (
        if /i "%%f" neq "README.md" (
            move "%%f" "docs\"
            echo    ✓ Moved %%f to docs/
        )
    )
)

if exist "*.txt" (
    for %%f in (*.txt) do (
        if /i "%%f" neq "requirements.txt" (
            move "%%f" "docs\"
            echo    ✓ Moved %%f to docs/
        )
    )
)

REM Move log files to logs folder
echo 📋 Organizing log files...
if exist "*.log" move "*.log" "logs\"
if exist "debug.txt" move "debug.txt" "logs\"
if exist "error.txt" move "error.txt" "logs\"

REM Move script files
echo 🔧 Organizing utility scripts...
if exist "setup.py" move "setup.py" "scripts\"
if exist "test.py" move "test.py" "scripts\"
if exist "utils.py" move "utils.py" "scripts\"
if exist "install.py" move "install.py" "scripts\"

REM Create requirements.txt if it doesn't exist
if not exist "requirements.txt" (
    echo 📦 Creating requirements.txt...
    echo pandas> requirements.txt
    echo numpy>> requirements.txt
    echo validators>> requirements.txt
    echo requests>> requirements.txt
    echo scikit-learn>> requirements.txt
    echo xgboost>> requirements.txt
    echo    ✓ Created requirements.txt
)

REM Create basic README.md if it doesn't exist
if not exist "README.md" (
    echo 📖 Creating README.md...
    echo # Enhanced Malicious URL Detection System 2025> README.md
    echo.>> README.md
    echo A comprehensive cybersecurity tool for detecting malicious URLs using ML and threat intelligence.>> README.md
    echo.>> README.md
    echo ## Quick Start>> README.md
    echo ```
    echo pip install -r requirements.txt>> README.md
    echo export VT_KEY_HEX="your_virustotal_api_key">> README.md
    echo python url_detector.py>> README.md
    echo ```>> README.md
    echo    ✓ Created README.md
)

REM Create .gitignore if it doesn't exist
if not exist ".gitignore" (
    echo 🚫 Creating .gitignore...
    echo # Python> .gitignore
    echo __pycache__/>> .gitignore
    echo *.py[cod]>> .gitignore
    echo *.so>> .gitignore
    echo.>> .gitignore
    echo # Data files>> .gitignore
    echo maliciouslinks.csv>> .gitignore
    echo *.log>> .gitignore
    echo.>> .gitignore
    echo # Environment>> .gitignore
    echo .env>> .gitignore
    echo venv/>> .gitignore
    echo env/>> .gitignore
    echo    ✓ Created .gitignore
)

echo.
echo ================================================
echo  📁 PROJECT ORGANIZATION COMPLETE
echo ================================================
echo.
echo 📂 Final Project Structure:
echo    malicious-url-detector/
echo    ├── url_detector.py          # Main detector script
echo    ├── requirements.txt         # Python dependencies
echo    ├── README.md               # Project documentation
echo    ├── .gitignore              # Git ignore rules
echo    ├── maliciouslinks.csv      # Analysis results (generated)
echo    ├── data/                   # Training data and datasets
echo    ├── docs/                   # Additional documentation
echo    ├── scripts/                # Utility scripts
echo    └── logs/                   # Log files
echo.
echo ✅ Ready for GitHub upload!
echo.
echo 🚀 Next steps:
echo    1. Review the organized structure
echo    2. Run: git init
echo    3. Run: git add .
echo    4. Run: git commit -m "Initial commit"
echo    5. Push to GitHub
echo.
pause
