object frmAdapterSelect: TfrmAdapterSelect
  Left = 0
  Top = 0
  BorderStyle = bsDialog
  Caption = 'SSniffer v0.0.3.8 beta'
  ClientHeight = 152
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
    Height = 136
    Caption = #1042#1099#1073#1086#1088' '#1072#1076#1072#1087#1090#1077#1088#1072':'
    TabOrder = 0
    object Label1: TLabel
      Left = 11
      Top = 43
      Width = 75
      Height = 13
      Caption = #1048#1084#1103' '#1072#1076#1072#1087#1090#1077#1088#1072':'
    end
    object Label2: TLabel
      Left = 11
      Top = 89
      Width = 53
      Height = 13
      Caption = #1054#1087#1080#1089#1072#1085#1080#1077':'
    end
    object lblAdapterName: TLabel
      Left = 24
      Top = 62
      Width = 78
      Height = 26
      Caption = 'AdapterName'#13#10'line2'
      Color = clBtnFace
      Font.Charset = DEFAULT_CHARSET
      Font.Color = clWindowText
      Font.Height = -11
      Font.Name = 'Tahoma'
      Font.Style = [fsBold]
      ParentColor = False
      ParentFont = False
      Transparent = True
      WordWrap = True
    end
    object lblAdapterDesc: TLabel
      Left = 24
      Top = 108
      Width = 73
      Height = 13
      Caption = 'AdapterDesc'
      Font.Charset = DEFAULT_CHARSET
      Font.Color = clWindowText
      Font.Height = -11
      Font.Name = 'Tahoma'
      Font.Style = [fsBold]
      ParentFont = False
    end
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
      OnChange = cbAdapterListChange
    end
  end
end
