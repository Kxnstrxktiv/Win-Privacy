@echo off

::ELEVATION
net session >nul 2>&1
if %errorLevel% == 0 (
    goto :elevated
) else (
    goto :not_elevated
)
:not_elevated
powershell "start-process cmd -argumentlist '/c %~f0' -verb runas -wait"
exit /b
:elevated

echo Running privacy fixes...

:REG
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f
if %errorlevel% neq 0 echo Error: Failed to disable telemetry via registry.
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v Enabled /t REG_DWORD /d 0 /f
if %errorlevel% neq 0 echo Error: Failed to disable advertising ID.
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SystemPaneSuggestionsEnabled /t REG_DWORD /d 0 /f
if %errorlevel% neq 0 echo Error: Failed to disable app suggestions.
reg add "HKCU\Software\Microsoft\Siuf\Rules" /v NumberOfSIUFInPeriod /t REG_DWORD /d 0 /f
if %errorlevel% neq 0 echo Error: Failed to disable feedback notifications.
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v Value /t REG_SZ /d Deny /f
if %errorlevel% neq 0 echo Error: Failed to disable location services.
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v AllowCloudSearch /t REG_DWORD /d 0 /f
if %errorlevel% neq 0 echo Error: Failed to disable cloud search.
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v Enabled /t REG_DWORD /d 0 /f
if %errorlevel% neq 0 echo Error: Failed to disable personalized ads.
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v EnableActivityFeed /t REG_DWORD /d 0 /f
if %errorlevel% neq 0 echo Error: Failed to disable activity history.
reg add "HKCU\Software\Microsoft\Clipboard" /v EnableClipboardHistory /t REG_DWORD /d 0 /f
if %errorlevel% neq 0 echo Error: Failed to disable clipboard cloud sync.
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v BingSearchEnabled /t REG_DWORD /d 0 /f
if %errorlevel% neq 0 echo Error: Failed to disable web search in Start menu.
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync" /v SyncPolicy /t REG_DWORD /d 5 /f
if %errorlevel% neq 0 echo Error: Failed to disable settings sync.
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" /v Value /t REG_SZ /d Deny /f
if %errorlevel% neq 0 echo Error: Failed to disable app access to account info.
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts" /v Value /t REG_SZ /d Deny /f
if %errorlevel% neq 0 echo Error: Failed to disable app access to contacts.
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v AllowDeviceNameInTelemetry /t REG_DWORD /d 0 /f
if %errorlevel% neq 0 echo Error: Failed to disable diagnostic data sharing.
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v CortanaConsent /t REG_DWORD /d 0 /f
if %errorlevel% neq 0 echo Error: Failed to set Cortana consent.

:PS
powershell -Command "Disable-WindowsOptionalFeature -Online -FeatureName 'Microsoft-Windows-Subsystem-Linux' -NoRestart" 2>nul
if %errorlevel% neq 0 echo Error: Failed to disable WSL feature.
powershell -Command "Set-MpPreference -DisablePrivacyMode $false" 2>nul
if %errorlevel% neq 0 echo Error: Failed to adjust Defender privacy mode.

:Fixes
echo Privacy fixes applied. Now running DISM and other fix commands...
DISM /Online /Cleanup-Image /CheckHealth
if %errorlevel% neq 0 echo Error: DISM CheckHealth failed.
DISM /Online /Cleanup-Image /ScanHealth
if %errorlevel% neq 0 echo Error: DISM ScanHealth failed.
DISM /Online /Cleanup-Image /RestoreHealth
if %errorlevel% neq 0 echo Error: DISM RestoreHealth failed.
sfc /scannow
if %errorlevel% neq 0 echo Error: SFC scan failed.

msg %username% "Script finished successfully."
exit