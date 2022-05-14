
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



REM if not defined iammaximized (
REM     set iammaximized=1
REM     start "" /max /wait "%~0"
REM     exit
REM )



REM change screen dimensions
mode con: cols=200 lines=9999


cd "C:\Tasandid4\fail2ban\wail2ban-master\"


:loop


REM powershell Set-ExecutionPolicy -Scope CurrentUser Unrestricted

powershell -executionpolicy bypass -file .\wail2ban.ps1 >> log.txt 2>&1


REM ping -n 2 127.0.0.1
sleep 1


goto loop




REM cd c:\scripts\wail2ban\
REM start powershell -executionpolicy bypass -file .\wail2ban.ps1
