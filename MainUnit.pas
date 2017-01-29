{   This file is part of KeePass4D.                                       

    KeePass4D is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    KeePass4D is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with KeePass4D.  If not, see <http://www.gnu.org/licenses/>. }
	
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
