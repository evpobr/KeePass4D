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

unit PasswordUnit;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes, Vcl.Graphics,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls, Vcl.Mask;

resourcestring
  SPasswordIsEmpty = 'Password cannot be empty!';
  
type
  TPasswordForm = class(TForm)
    lblPassword: TLabel;
    edPassword: TMaskEdit;
    btnOK: TButton;
    btnCancel: TButton;
  private
    function GetPassword: string;
    { Private declarations }
  public
    { Public declarations }
    property Password: string read GetPassword;
  end;

var
  PasswordForm: TPasswordForm;

implementation

{$R *.dfm}

{ TPasswordForm }

function TPasswordForm.GetPassword: string;
begin
  Result := edPassword.Text;
end;

end.
