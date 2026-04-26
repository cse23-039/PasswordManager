; Inno Setup 6 script for Password Manager
; Run: iscc installer\windows\setup.iss
; Requires: Inno Setup 6 — https://jrsoftware.org/isdl.php

#define AppName      "Password Manager"
#ifndef AppVersion
  #define AppVersion "1.0.0"
#endif
#define AppPublisher "Kagiso Setwaba"
#define AppExeName   "password-manager.exe"
#define AppGUID      "{A3B2C1D0-1234-5678-ABCD-EF0123456789}"

[Setup]
AppId={{#AppGUID}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL=https://github.com/KagisoSetwaba/password-manager
AppSupportURL=https://github.com/KagisoSetwaba/password-manager/issues
AppUpdatesURL=https://github.com/KagisoSetwaba/password-manager/releases
AppCopyright=Copyright (C) 2024 {#AppPublisher}

; Installation directory
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
AllowNoIcons=yes

; Show all wizard pages including dir and components
DisableDirPage=no
DisableProgramGroupPage=no

; Output
OutputDir=Output
OutputBaseFilename=PasswordManager-Setup-{#AppVersion}
SetupIconFile=..\..\cmd\password-manager\logo.ico

; Compression
Compression=lzma2/ultra64
SolidCompression=yes

; UI
WizardStyle=modern
WizardSizePercent=120
ShowLanguageDialog=no

; Windows version and privileges
MinVersion=10.0
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible

; Uninstall display
UninstallDisplayIcon={app}\{#AppExeName}
UninstallDisplayName={#AppName} {#AppVersion}

; Version info embedded in Setup.exe
VersionInfoVersion={#AppVersion}
VersionInfoCompany={#AppPublisher}
VersionInfoDescription={#AppName} Installer
VersionInfoProductName={#AppName}
VersionInfoProductVersion={#AppVersion}

; Prevent running multiple instances of the installer
SetupMutex=PasswordManagerSetupMutex

; Code-signing: uncomment and set paths once you have a certificate
; SignTool=signtool sign /tr http://timestamp.sectigo.com /td sha256 /fd sha256 /f "cert.pfx" /p "password" $f

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon";   Description: "{cm:CreateDesktopIcon}";        GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "startmenuicon"; Description: "Create a &Start Menu shortcut"; GroupDescription: "{cm:AdditionalIcons}"; Flags: checkedonce

[Files]
Source: "..\..\bin\{#AppExeName}";             DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\cmd\password-manager\logo.ico"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#AppName}";             Filename: "{app}\{#AppExeName}"; Tasks: startmenuicon
Name: "{group}\Uninstall {#AppName}";   Filename: "{uninstallexe}";      Tasks: startmenuicon
Name: "{commondesktop}\{#AppName}";     Filename: "{app}\{#AppExeName}"; Tasks: desktopicon

[Registry]
; Add to "Apps & features" / Programs and Features with full metadata
Root: HKLM; Subkey: "Software\Microsoft\Windows\CurrentVersion\Uninstall\{{#AppGUID}_is1"; ValueType: string; ValueName: "DisplayName";     ValueData: "{#AppName} {#AppVersion}"; Flags: uninsdeletevalue
Root: HKLM; Subkey: "Software\Microsoft\Windows\CurrentVersion\Uninstall\{{#AppGUID}_is1"; ValueType: string; ValueName: "Publisher";        ValueData: "{#AppPublisher}";          Flags: uninsdeletevalue
Root: HKLM; Subkey: "Software\Microsoft\Windows\CurrentVersion\Uninstall\{{#AppGUID}_is1"; ValueType: string; ValueName: "DisplayVersion";    ValueData: "{#AppVersion}";            Flags: uninsdeletevalue
Root: HKLM; Subkey: "Software\Microsoft\Windows\CurrentVersion\Uninstall\{{#AppGUID}_is1"; ValueType: string; ValueName: "HelpLink";          ValueData: "https://github.com/KagisoSetwaba/password-manager/issues"; Flags: uninsdeletevalue
Root: HKLM; Subkey: "Software\Microsoft\Windows\CurrentVersion\Uninstall\{{#AppGUID}_is1"; ValueType: string; ValueName: "URLInfoAbout";      ValueData: "https://github.com/KagisoSetwaba/password-manager";        Flags: uninsdeletevalue

[Run]
Filename: "{app}\{#AppExeName}"; \
  Description: "{cm:LaunchProgram,{#StringChange(AppName, '&', '&&')}}"; \
  Flags: nowait postinstall skipifsilent runascurrentuser

[UninstallDelete]
; Vault data is controlled by the optional checkbox in the uninstaller (see [Code] section below).
; Automatic silent deletion is intentionally disabled — the checkbox gives the user explicit control.

[Code]

// ---------------------------------------------------------------------------
// Uninstaller — optional vault data deletion checkbox
// ---------------------------------------------------------------------------
var
  DeleteDataCheckBox: TNewCheckBox;
  DeleteDataWarning:  TNewStaticText;

procedure InitializeUninstallProgressForm();
var
  Sep:         TBevel;
  OptLabel:    TNewStaticText;
  InnerPage:   TNewNotebookPage;
  BaseTop:     Integer;
begin
  InnerPage := UninstallProgressForm.InnerPage;
  BaseTop   := UninstallProgressForm.ProgressBar.Top +
               UninstallProgressForm.ProgressBar.Height + 16;

  // Separator line
  Sep        := TBevel.Create(UninstallProgressForm);
  Sep.Parent := InnerPage;
  Sep.Left   := 0;
  Sep.Top    := BaseTop;
  Sep.Width  := InnerPage.Width;
  Sep.Height := 2;
  Sep.Shape  := bsTopLine;

  // "Optional" heading
  OptLabel            := TNewStaticText.Create(UninstallProgressForm);
  OptLabel.Parent     := InnerPage;
  OptLabel.Left       := 0;
  OptLabel.Top        := Sep.Top + Sep.Height + 8;
  OptLabel.Width      := InnerPage.Width;
  OptLabel.Caption    := 'Optional:';
  OptLabel.Font.Style := [fsBold];

  // Delete data checkbox
  DeleteDataCheckBox         := TNewCheckBox.Create(UninstallProgressForm);
  DeleteDataCheckBox.Parent  := InnerPage;
  DeleteDataCheckBox.Left    := 0;
  DeleteDataCheckBox.Top     := OptLabel.Top + OptLabel.Height + 4;
  DeleteDataCheckBox.Width   := InnerPage.Width;
  DeleteDataCheckBox.Caption :=
    'Delete all vault data from AppData\PasswordManager' +
    ' (passwords, user accounts and audit logs will be permanently removed)';
  DeleteDataCheckBox.Checked := False;

  // Warning text shown beneath checkbox
  DeleteDataWarning            := TNewStaticText.Create(UninstallProgressForm);
  DeleteDataWarning.Parent     := InnerPage;
  DeleteDataWarning.Left       := 16;
  DeleteDataWarning.Top        := DeleteDataCheckBox.Top + DeleteDataCheckBox.Height + 4;
  DeleteDataWarning.Width      := InnerPage.Width - 16;
  DeleteDataWarning.Caption    :=
    'Warning: this action is irreversible. Leave unchecked to keep your data.';
  DeleteDataWarning.Font.Color := $0000CC;   // dark red (BGR)
  DeleteDataWarning.Font.Style := [fsItalic];
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  DataPath: string;
begin
  if CurUninstallStep = usPostUninstall then
  begin
    if Assigned(DeleteDataCheckBox) and DeleteDataCheckBox.Checked then
    begin
      DataPath := ExpandConstant('{userappdata}\PasswordManager');
      if DirExists(DataPath) then
      begin
        if not DelTree(DataPath, True, True, True) then
          MsgBox(
            'Some files could not be removed automatically.' + #13#10 +
            'Please delete this folder manually:' + #13#10 + #13#10 + DataPath,
            mbError, MB_OK
          );
      end;
    end;
  end;
end;
