@echo off
rem LAN Explorer one-click launcher
cd /d "%~dp0"
where python >nul 2>nul && (set PY=python) || (set PY=py -3)
start "" "http://127.0.0.1:8791"
%PY% server.py
if errorlevel 1 pause
