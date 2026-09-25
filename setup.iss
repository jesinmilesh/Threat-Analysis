[Setup]
AppName=Threat Analysis
AppVersion=1.0
AppPublisher=Cyber Team
DefaultDirName={autopf}\Threat Analysis
DefaultGroupName=Threat Analysis
OutputDir=dist
OutputBaseFilename=ThreatAnalysis
Compression=lzma
SolidCompression=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
SetupIconFile=threat_logo.ico


[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "dist\threat_analysis\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "threat_logo.ico"; DestDir: "{app}"; Flags: ignoreversion
[Icons]
Name: "{group}\Threat Analysis"; Filename: "{app}\threat_analysis.exe"; IconFilename: "{app}\threat_logo.ico"
Name: "{commondesktop}\Threat Analysis"; Filename: "{app}\threat_analysis.exe"; IconFilename: "{app}\threat_logo.ico"; Tasks: desktopicon

[Run]
Filename: "{app}\threat_analysis.exe"; Description: "{cm:LaunchProgram,Threat Analysis}"; Flags: nowait postinstall skipifsilent
