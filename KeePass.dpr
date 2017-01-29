program KeePass;

uses
  Vcl.Forms,
  MainUnit in 'MainUnit.pas' {MainForm},
  KeePassLib in 'KeePassLib.pas',
  KeePassLib.Wincrypt in 'KeePassLib.Wincrypt.pas',
  System.Security.Cryptography in 'System.Security.Cryptography.pas',
  KeePassLib.BCrypt in 'KeePassLib.BCrypt.pas',
  PasswordUnit in 'Forms\PasswordUnit.pas' {PasswordForm};

{$R *.res}

begin
  Application.Initialize;
  Application.MainFormOnTaskbar := True;
  Application.CreateForm(TMainForm, MainForm);
  Application.Run;
end.
