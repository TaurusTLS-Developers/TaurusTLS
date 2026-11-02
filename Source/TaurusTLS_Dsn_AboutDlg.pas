unit TaurusTLS_Dsn_AboutDlg;

interface

uses
  {$IFDEF FPC}
  Classes,
  Graphics, Controls, Forms, StdCtrls, ExtCtrls
  {$ELSE}
  System.Classes,
  Vcl.Graphics, Vcl.Controls, Vcl.Forms, Vcl.StdCtrls, Vcl.ExtCtrls,
  Vcl.Imaging.pngimage
  {$ENDIF}
  ;

type
  TfrmAbout = class(TForm)
    pnlHeader: TPanel;
    imgLogo: TImage;
    pnlHeaderText: TPanel;
    lblVersion: TLabel;
    lblHeader: TLabel;
    lblCopyright: TLabel;
    pnlBottom: TPanel;
    memAcknowledgements: TMemo;
    btnOk: TButton;
    lblLicense: TLabel;
  private
    { Private declarations }
    {$IFNDEF FPC}
    procedure SetLogo;
    {$ENDIF}
  public
    { Public declarations }
    class procedure Show; overload;
    constructor Create; reintroduce;
  end;

procedure AboutDlg;

implementation

{$IFDEF FPC}
  {$R *.lfm}
{$ELSE}
  {$R *.dfm}
{$ENDIF}

uses
  {$IFDEF FPC}
  SysUtils,
  {$ELSE}
  System.SysUtils, Winapi.Windows,
  {$ENDIF}
  TaurusTLS_Dsn_Const,
  TaurusTLS_Dsn_ResourceStrings;

procedure AboutDlg;
begin
  TfrmAbout.Show;
end;

{ TfrmAbout }

constructor TfrmAbout.Create;
begin
  inherited Create(nil);
  {$IFNDEF FPC}
  SetLogo;
  {$ENDIF}
  lblHeader.Caption:=gsTaurusTLSProductName;
  lblVersion.Caption:=GetTaurusTLSVersion(RSTaurusTLSVersionPrefix);
  lblCopyright.Caption:=RSCopyright;
  lblLicense.Caption:=RSLicense;
  memAcknowledgements.Lines.Text:=GetThirdPartyAcknowlegements(True);
  btnOk.Caption:=RSOk;
end;

{$IFNDEF FPC}
procedure TfrmAbout.SetLogo;
var
  LBitmap: Vcl.Graphics.TBitmap;
  LText: string;
  LModule: HMODULE;
  LStream: TResourceStream;
begin
  LModule := FindClassHInstance(TfrmAbout);
  if FindResource(LModule, 'SPLASH128', RT_RCDATA) <> 0 then
  begin
    LStream := TResourceStream.Create(LModule, 'SPLASH128', RT_RCDATA);
    try
      imgLogo.Picture.LoadFromStream(LStream);
    finally
      LStream.Free;
    end;
    Exit;
  end;

  LBitmap := Vcl.Graphics.TBitmap.Create;
  try
    LBitmap.Width := 128;
    LBitmap.Height := 128;
    LBitmap.Canvas.Brush.Color := clBtnFace;
    LBitmap.Canvas.FillRect(Rect(0, 0, 128, 128));
    LBitmap.Canvas.Pen.Color := clBtnShadow;
    LBitmap.Canvas.Rectangle(4, 4, 124, 124);
    LBitmap.Canvas.Font.Assign(Font);
    LBitmap.Canvas.Font.Color := clWindowText;
    LBitmap.Canvas.Font.Size := 24;
    LBitmap.Canvas.Font.Style := [fsBold];
    LText := 'TLS';
    LBitmap.Canvas.TextOut(
      (128 - LBitmap.Canvas.TextWidth(LText)) div 2,
      (128 - LBitmap.Canvas.TextHeight(LText)) div 2, LText);
    imgLogo.Picture.Assign(LBitmap);
  finally
    LBitmap.Free;
  end;
end;
{$ENDIF}

class procedure TfrmAbout.Show;
var
  lInstance: TfrmAbout;

begin
  lInstance:=TfrmAbout.Create;
  try
    lInstance.ShowModal;
  finally
    lInstance.Free;
  end;
end;

end.
