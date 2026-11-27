object frmAbout: TfrmAbout
  Left = 0
  Top = 0
  BorderStyle = bsDialog
  Caption = 'TaurusTLS'
  ClientHeight = 428
  ClientWidth = 589
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -12
  Font.Name = 'Segoe UI'
  Font.Style = []
  Position = poScreenCenter
  TextHeight = 15
  object pnlHeader: TPanel
    Left = 0
    Top = 0
    Width = 589
    Height = 180
    Align = alTop
    BevelOuter = bvNone
    TabOrder = 0
    object imgLogo: TImage
      Left = 0
      Top = 0
      Width = 128
      Height = 180
      Margins.Left = 5
      Margins.Top = 5
      Margins.Right = 5
      Margins.Bottom = 5
      Align = alLeft
      AutoSize = True
      Center = True
      Constraints.MaxHeight = 256
      Constraints.MinHeight = 128
      Constraints.MinWidth = 128
      ExplicitTop = -8
      ExplicitHeight = 219
    end
    object pnlHeaderText: TPanel
      AlignWithMargins = True
      Left = 136
      Top = 3
      Width = 438
      Height = 169
      Margins.Left = 8
      Margins.Right = 15
      Margins.Bottom = 8
      Align = alClient
      BevelOuter = bvNone
      TabOrder = 0
      object lblVersion: TLabel
        AlignWithMargins = True
        Left = 3
        Top = 39
        Width = 432
        Height = 32
        Margins.Top = 7
        Margins.Bottom = 7
        Align = alTop
        Alignment = taCenter
        Caption = 'gsTaurusTLSVersion'
        Font.Charset = DEFAULT_CHARSET
        Font.Color = clWindowText
        Font.Height = -24
        Font.Name = 'Segoe UI'
        Font.Style = []
        ParentFont = False
        ExplicitWidth = 207
      end
      object lblHeader: TLabel
        Left = 0
        Top = 0
        Width = 438
        Height = 32
        Margins.Top = 10
        Margins.Bottom = 10
        Align = alTop
        Alignment = taCenter
        Caption = 'RSTaurusTLS'
        Font.Charset = DEFAULT_CHARSET
        Font.Color = clWindowText
        Font.Height = -24
        Font.Name = 'Segoe UI'
        Font.Style = [fsBold]
        ParentFont = False
        ExplicitWidth = 144
      end
      object lblCopyright: TLabel
        AlignWithMargins = True
        Left = 3
        Top = 85
        Width = 432
        Height = 19
        Margins.Top = 7
        Margins.Bottom = 7
        Align = alTop
        Alignment = taCenter
        Caption = 'RSCopyright'
        Font.Charset = DEFAULT_CHARSET
        Font.Color = clWindowText
        Font.Height = -14
        Font.Name = 'Segoe UI'
        Font.Style = []
        ParentFont = False
        ExplicitWidth = 76
      end
      object lblLicense: TLabel
        AlignWithMargins = True
        Left = 3
        Top = 114
        Width = 432
        Height = 52
        Align = alClient
        Alignment = taCenter
        Caption = 'RSLicense'
        WordWrap = True
        ExplicitWidth = 52
        ExplicitHeight = 15
      end
    end
  end
  object pnlBottom: TPanel
    Left = 0
    Top = 392
    Width = 589
    Height = 36
    Align = alBottom
    BevelOuter = bvNone
    TabOrder = 1
    DesignSize = (
      589
      36)
    object btnOk: TButton
      Left = 496
      Top = 6
      Width = 75
      Height = 25
      Anchors = [akTop, akRight]
      Cancel = True
      Caption = 'Ok'
      Default = True
      ModalResult = 1
      TabOrder = 0
    end
  end
  object memAcknowledgements: TMemo
    Left = 0
    Top = 180
    Width = 589
    Height = 212
    Align = alClient
    Font.Charset = DEFAULT_CHARSET
    Font.Color = clWindowText
    Font.Height = -11
    Font.Name = 'Segoe UI'
    Font.Style = []
    Lines.Strings = (
      'RSThirdPartyAcknowlegements')
    ParentFont = False
    ReadOnly = True
    ScrollBars = ssVertical
    TabOrder = 2
  end
end
