@echo off
:: Change directory to where pySync is installed
cd /d "C:\Users\YourUser\Documents\pySync"

:: Run the script using pythonw (no window) or python (with console)
:: Using pythonw is better for background service
start "" pythonw pySync.py

exit
