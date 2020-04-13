@ECHO OFF
CLS
COLOR 0E
PowerShell.exe -ExecutionPolicy Bypass -file %0\..\AD-Exp-Notify.ps1

ECHO.
ECHO FINISHED!