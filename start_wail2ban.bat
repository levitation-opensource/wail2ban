@echo off


title Wail2Ban



REM change active dir to current location
%~d0
cd /d "%~dp0"



if "%~1" neq "oneinstance" (

	if exist SingleInstanceCmd.exe (
		SingleInstanceCmd.exe "%~n0" "%~0" "oneinstance"
		goto :eof
	)
)



REM change screen dimensions
mode con: cols=200 lines=9999



:loop


REM powershell Set-ExecutionPolicy -Scope CurrentUser Unrestricted

powershell -executionpolicy bypass -file .\wail2ban.ps1 >> log.txt 2>&1


ping -n 2 127.0.0.1
REM sleep 1


goto loop
