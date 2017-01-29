object PasswordForm: TPasswordForm
  Left = 0
  Top = 0
  BorderStyle = bsDialog
  Caption = 'Enter password'
  ClientHeight = 221
  ClientWidth = 385
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'Tahoma'
  Font.Style = []
  OldCreateOrder = False
  Position = poMainFormCenter
  PixelsPerInch = 96
  TextHeight = 13
  object lblPassword: TLabel
    Left = 8
    Top = 8
    Width = 79
    Height = 13
    Caption = 'Enter password:'
  end
  object edPassword: TMaskEdit
    Left = 8
    Top = 27
    Width = 369
    Height = 21
    PasswordChar = '*'
    TabOrder = 0
    Text = ''
  end
  object btnOK: TButton
    Left = 216
    Top = 188
    Width = 75
    Height = 25
    Caption = '&OK'
    Default = True
    ModalResult = 1
    TabOrder = 1
  end
  object btnCancel: TButton
    Left = 302
    Top = 188
    Width = 75
    Height = 25
    Cancel = True
    Caption = '&Cancel'
    ModalResult = 2
    TabOrder = 2
  end
end
