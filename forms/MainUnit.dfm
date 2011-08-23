object frmMain: TfrmMain
  Left = 283
  Top = 288
  BorderStyle = bsSingle
  Caption = 'sniff'
  ClientHeight = 254
  ClientWidth = 396
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'Tahoma'
  Font.Style = []
  OldCreateOrder = False
  OnCreate = FormCreate
  OnDestroy = FormDestroy
  PixelsPerInch = 96
  TextHeight = 13
  object mmo1: TMemo
    Left = 215
    Top = 19
    Width = 130
    Height = 94
    BorderStyle = bsNone
    Font.Charset = DEFAULT_CHARSET
    Font.Color = clWindowText
    Font.Height = 12
    Font.Name = '@FangSong'
    Font.Pitch = fpFixed
    Font.Style = []
    Font.Quality = fqClearTypeNatural
    Lines.Strings = (
      #1055#1088#1080#1074#1077#1090)
    ParentFont = False
    ScrollBars = ssVertical
    TabOrder = 0
  end
  object GroupBox1: TGroupBox
    Left = 8
    Top = 8
    Width = 145
    Height = 105
    Caption = #1057#1090#1072#1090#1080#1089#1090#1080#1082#1072
    TabOrder = 1
    object lblPacketsCount: TLabel
      Left = 8
      Top = 24
      Width = 77
      Height = 13
      Caption = #1042#1089#1077#1075#1086' '#1087#1072#1082#1077#1090#1086#1074':'
    end
    object lblAIMPacketsCount: TLabel
      Left = 17
      Top = 43
      Width = 68
      Height = 13
      Caption = 'AIM '#1087#1072#1082#1077#1090#1086#1074':'
    end
    object Label1: TLabel
      Left = 13
      Top = 62
      Width = 72
      Height = 13
      Caption = 'MRA '#1055#1072#1082#1077#1090#1086#1074':'
    end
    object lblVK: TLabel
      Left = 33
      Top = 81
      Width = 52
      Height = 13
      Caption = 'Vkontakte:'
    end
    object lblVKCounter: TLabel
      Left = 91
      Top = 81
      Width = 6
      Height = 13
      Caption = '0'
    end
    object lblMRACounter: TLabel
      Left = 91
      Top = 62
      Width = 6
      Height = 13
      Caption = '0'
    end
    object lbAIMCounter: TLabel
      Left = 91
      Top = 43
      Width = 6
      Height = 13
      Caption = '0'
    end
    object lbCounter: TLabel
      Left = 91
      Top = 24
      Width = 6
      Height = 13
      Caption = '0'
    end
  end
  object tmrCounter: TTimer
    Enabled = False
    OnTimer = tmrCounterTimer
    Left = 168
    Top = 16
  end
end
