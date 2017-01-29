unit MainUnit;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes, Vcl.Graphics,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls, System.Generics.Collections, System.Types, KeePassLib,
  PasswordUnit, System.Actions, Vcl.ActnList, Vcl.ToolWin, Vcl.ActnMan,
  Vcl.ActnCtrls, Vcl.ActnMenus, Vcl.PlatformDefaultStyleActnCtrls, Vcl.StdActns,
  System.ImageList, Vcl.ImgList, Vcl.ComCtrls, Vcl.AppEvnts, System.IOUtils,
  System.UITypes;

const
  DefaultApplicationTitle = 'KeePass4D';

type
  TMainForm = class(TForm)
    ActionManager: TActionManager;
    ActionMainMenuBar: TActionMainMenuBar;
    MainImageList: TImageList;
    FileOpen: TFileOpen;
    StatusBar: TStatusBar;
    MainActionToolBar: TActionToolBar;
    ApplicationEvents: TApplicationEvents;
    FileExit1: TFileExit;
    procedure FileOpenAccept(Sender: TObject);
    procedure ApplicationEventsHint(Sender: TObject);
    procedure FormCreate(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
  private
    { Private declarations }
    FKdbx: TKdbxFile;
    FFileName: string;
  public
    { Public declarations }
  end;

var
  MainForm: TMainForm;

implementation

{$R *.dfm}

uses
  KeePassLib.Wincrypt, KeePassLib.Bcrypt, System.Hash,
  System.Security.Cryptography;

procedure TMainForm.ApplicationEventsHint(Sender: TObject);
begin
  StatusBar.Panels[1].Text := Application.Hint;
end;

procedure TMainForm.FileOpenAccept(Sender: TObject);
var
  PasswordIsCorrect: Boolean;
  mr: Integer;
begin
  PasswordIsCorrect := False;

  PasswordForm := TPasswordForm.Create(Self);
  try

    repeat
      mr := PasswordForm.ShowModal;
      if  mr = mrCancel then
        Break;

      try
        FKdbx.LoadFromFile(PasswordForm.Password, FileOpen.Dialog.FileName);
        PasswordIsCorrect := True;
        FFileName := FileOpen.Dialog.FileName;
        Caption := Format('%s - %s', [DefaultApplicationTitle, TPath.GetFileNameWithoutExtension(FFileName)]);
      except
        on E: EKdbxPasswordError do
        begin
          PasswordIsCorrect := False;
          MessageDlg('Password is incorrect!', mtError, [mbOk], 0);
        end
      end;
    until PasswordIsCorrect = True;

  finally
    PasswordForm.Free;
  end;
end;

procedure TMainForm.FormCreate(Sender: TObject);
begin
  FKdbx := TKdbxFile.Create;
end;

procedure TMainForm.FormDestroy(Sender: TObject);
begin
  FKdbx.Free;
end;

end.
