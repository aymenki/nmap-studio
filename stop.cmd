@echo off
cd /d "%~dp0"
py -3 launch.py --stop 2>nul || python launch.py --stop
