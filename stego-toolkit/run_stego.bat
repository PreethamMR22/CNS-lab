@echo off
echo ====================================
echo Steganography Detection Toolkit
echo ====================================
echo.
echo Activating virtual environment...
call stego-env\Scripts\Activate.bat
echo.
echo Virtual environment activated!
echo.
echo Available commands:
echo   python stego_detector.py detect image.jpg
echo   python advanced_stego.py image.jpg
echo   python quick_start.py
echo.
echo Current directory: %CD%
echo.
echo You can now run steganography commands!
echo.
cmd /k
