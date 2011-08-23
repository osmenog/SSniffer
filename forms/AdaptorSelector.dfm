object frmAdapterSelect: TfrmAdapterSelect
  Left = 0
  Top = 0
  BorderStyle = bsToolWindow
  Caption = 'SSniffer v0.0.3.8 beta'
  ClientHeight = 64
  ClientWidth = 367
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'Tahoma'
  Font.Style = []
  OldCreateOrder = False
  OnClose = FormClose
  OnCreate = FormCreate
  PixelsPerInch = 96
  TextHeight = 13
  object grp1: TGroupBox
    Left = 8
    Top = 8
    Width = 353
    Height = 48
    Caption = #1042#1099#1073#1086#1088' '#1072#1076#1072#1087#1090#1077#1088#1072':'
    TabOrder = 0
    object btnSave: TButton
      Left = 262
      Top = 16
      Width = 81
      Height = 21
      Caption = #1054#1050
      TabOrder = 1
      OnClick = btnSaveClick
    end
    object cbAdapterList: TComboBox
      Left = 11
      Top = 16
      Width = 245
      Height = 21
      Style = csDropDownList
      Font.Charset = DEFAULT_CHARSET
      Font.Color = clWindowText
      Font.Height = -11
      Font.Name = 'Tahoma'
      Font.Style = []
      ParentFont = False
      TabOrder = 0
    end
  end
end
