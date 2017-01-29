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
