; Antigravity Vault - Inno Setup Windows Installer Script
; Architecture: x64 Windows 10/11
#define MyAppName "Antigravity Vault"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "Antigravity Engineering"
#define MyAppURL "https://github.com/daya/rustpwdvault"
#define MyAppExeName "pwdvault_flutter.exe"

[Setup]
AppId={{E73EDAAF-6F0C-4C82-8252-93DCA59C0128}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\{#MyAppName}
DisableProgramGroupPage=yes
LicenseFile=..\..\LICENSE
OutputDir=..\..\dist\windows
OutputBaseFilename=AntigravityVault-Setup-x64
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
ArchitecturesInstallIn64BitMode=x64compatible
ArchitecturesAllowed=x64compatible
PrivilegesRequired=lowest

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "registerbrowser"; Description: "Register Browser Extension Native Messaging Host"; GroupDescription: "Browser Integration"; Flags: checkedonce

[Files]
; Flutter Desktop Release Binaries
Source: "..\..\apps\flutter\build\windows\x64\runner\Release\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
; Rust FFI Dynamic Library
Source: "..\..\apps\flutter\pwdvault_ffi.dll"; DestDir: "{app}"; Flags: ignoreversion
; Rust Native Messaging Host
Source: "..\..\core\target\release\pwdvault-native-host.exe"; DestDir: "{app}"; Flags: ignoreversion
; Native Messaging Manifests
Source: "..\..\apps\browser_extension\manifest\com.antigravity.pwdvault.json"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\apps\browser_extension\manifest\com.antigravity.pwdvault.firefox.json"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Registry]
; Google Chrome Native Messaging Registration
Root: HKCU; Subkey: "Software\Google\Chrome\NativeMessagingHosts\com.antigravity.pwdvault"; ValueType: string; ValueName: ""; ValueData: "{app}\com.antigravity.pwdvault.json"; Flags: uninsdeletekey; Tasks: registerbrowser
; Microsoft Edge Native Messaging Registration
Root: HKCU; Subkey: "Software\Microsoft\Edge\NativeMessagingHosts\com.antigravity.pwdvault"; ValueType: string; ValueName: ""; ValueData: "{app}\com.antigravity.pwdvault.json"; Flags: uninsdeletekey; Tasks: registerbrowser
; Mozilla Firefox Native Messaging Registration
Root: HKCU; Subkey: "Software\Mozilla\NativeMessagingHosts\com.antigravity.pwdvault"; ValueType: string; ValueName: ""; ValueData: "{app}\com.antigravity.pwdvault.firefox.json"; Flags: uninsdeletekey; Tasks: registerbrowser

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent
