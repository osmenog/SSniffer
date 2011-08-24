{ TODO : ������� ~MagClasses.pas � ~MagentaMonsock.pas �� ������� }
{ DONE : ���������� �������� ���� }
{ DONE : �������� ��������� ���������� ������:
  (-i)nterface [<��� ��������>] - ����� �������� ��������.
    ���� ����� ���������� ��� ���������, �� ��������� ������.
  (-v)ersion - ����� ������ ��������. � ��� �������� :)
  (-r)untime log - �������� ���� ��� �������
  (-c)rypto - ������������� ���������� � ����� ��������� ����.}
{ DONE : �������� � github }

unit MainUnit;

interface

uses
  Windows, Messages, SysUtils, Variants, Classes, Graphics, Controls, Forms,
  Dialogs,
  MagentaMonpcap, MagentaPacket32, MagentaPcap,
  MagentaPackhdrs, magsubs1, winsock, icqparser, SSUtils, mraParcer,SClasses,
  ExtCtrls, StdCtrls;

type
  TfrmMain = class(TForm)
    tmrCounter: TTimer;
    mmo1: TMemo;
    GroupBox1: TGroupBox;
    lblPacketsCount: TLabel;
    lblAIMPacketsCount: TLabel;
    Label1: TLabel;
    lblVK: TLabel;
    lblVKCounter: TLabel;
    lblMRACounter: TLabel;
    lbAIMCounter: TLabel;
    lbCounter: TLabel;
    procedure FormCreate(Sender: TObject);
    procedure tmrCounterTimer(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
  private
    FSettings: TSettings;
    FLog:      TDebugLog;
  public
    procedure PacketEvent(Sender: TObject; PacketInfo: TPacketInfo);
    procedure Start;
  end;

const
  // PPPOE - 7b
  // IP - 20b
  // TCP - �� 20 �� 60b
  OFFSET_IP = 7;
  OFFSET_TCP = OFFSET_IP + 20;

  PORT_AIM = 5190; // ����� ����� ��������� AIM

var
  frmMain: TfrmMain;
  MonitorPcap: TMonitorPcap; // ������� ��������
  MonStarted: Boolean;
  AIMpckCount: integer; // ������� ������� AIM
  MRApckCount: integer; // ������� ������� MRA
  VKpckCount : Integer;

implementation
uses AdaptorSelector;
{$R *.dfm}

procedure TfrmMain.FormCreate(Sender: TObject);
var
  i: integer;
  tmp: string;
  PathToExe:String;
begin
  //��������� �������� � ������������� ��������
  PathToExe:=ExtractFileDir(ParamStr(0));
  FSettings:=TSettings.Create;
  with FSettings do
  begin
    //CheckDublicate;
    ReadCMDParams;
    LoadFromINI(PathToExe+'\'+SETTINGS_FILENAME);
    SaveToINI(PathToExe+'\'+SETTINGS_FILENAME);
  end;

  //��������� ������������� ����
  FLog:=TDebugLog.Create;
  FLog.ApplySettings(FSettings);
  FLog.Add (#13#10+'**********',False);

  //���� ������������ ���� ����������� ����, �� ������ ��. ����� �������.
  if FSettings.CMD_ShowWindow=False then
    Application.ShowMainForm:=False
  else
    Application.ShowMainForm:=True;

  // ���������, �������� �� ������� PCAP
  if not LoadPacketDll then
  begin
    FLog.Add('Error: packet.dll is not loaded');
    if FSettings.CMD_ShowWindow then ShowMessage('packed.dll not found');
    Application.Terminate;
    Exit;
  end;

  //�������������
  MonStarted:= false; // ��������� �������� - ��������
  MonitorPcap := TMonitorPcap.Create(self); // ������� "�������"
  MonitorPcap.onPacketEvent := PacketEvent; // ������ ���������� �������

  FLog.Add('WinPCAP loaded. Version: ' + Pcap_GetPacketVersion);
end;
procedure TfrmMain.FormDestroy(Sender: TObject);
begin
  if MonStarted = true then
  begin
    MonitorPCAP.StopMonitor;
    MonitorPCAP.Free;
  end;

  FLog.Add('Exit');
  FLog.Free;
  Application.Terminate;
end;
procedure TfrmMain.PacketEvent(Sender: TObject; PacketInfo: TPacketInfo);
var
  i: integer;
  DataLen: integer;
  OFFSET_DATA: integer;
  ip: PHdrIP; // ��������� �� ��������� HdrIP
  tcp: PHdrTCP;
  TCPHdrLen: integer;
  DataBufEx: AnsiString;
  magic:DWORD;
begin
  {if PacketInfo.EtherProto = PROTO_PPPOE then // ���� ������ �������� PPPOE
  begin
    // ���� ��������� �������� ��- IP (0x0021) �� �������
    if ord(PacketInfo.DataBuf[7]) <> $0021 then
      exit;

    // �������� ��������� �� ������ IP ���������.
    ip := PHdrIP(PAnsiChar(@PacketInfo.DataBuf[1]) + OFFSET_IP);
    IF ip.protocol <> $06 then
      exit; // �������, ���� IP ��������� ������� � ��� ��� ����� ���� �� TCP �����

    // �������� ��������� �� ������ TCP ���������
    tcp := PHdrTCP(PAnsiChar(@PacketInfo.DataBuf[1]) + OFFSET_TCP);
    // ���������� ����� TCP ��������� (� ������)
    TCPHdrLen := (ntohs(tcp.flags) shr 12) * 4;
    // ������� �������� �� ������ ������ ������.
    OFFSET_DATA := OFFSET_TCP + TCPHdrLen;
    // ����������, ���� �� ������ ����� TCP ���������
    DataLen := PacketInfo.DataLen - OFFSET_DATA;

    if DataLen <= 0 then
      exit; // �������, ���� ������ �����������

    // ������� ������ ������, ���������� ���� ������
    SetLength(DataBufEx, DataLen);
    Move(PacketInfo.DataBuf[OFFSET_DATA + 1], DataBufEx[1], DataLen);

    // �������� ��������� ��������� ������
    i := ProcessBuffer(DataBufEx, ip.saddr, ip.daddr, ntohs(tcp.source),
      ntohs(tcp.dest), PacketInfo.EtherSrc, PacketInfo.EtherDest, PacketInfo.EtherProto);
  end
  else
  begin // ���� ������ �������� IP
    with PacketInfo do // �������� ��������� ��������� ������
      i := ProcessBuffer(DataBuf, AddrSrc, AddrDest, PortSrc, PortDest,
        PacketInfo.EtherSrc, PacketInfo.EtherDest,PacketInfo.EtherProto);
  end;}

  // �������� ����� ��������� ��������
  // if (psrc=PORT_AIM) or (pdst=PORT_AIM) then
  // begin
  // �������������� �������� �� AIM �����
  if (Length(PacketInfo.DataBuf) <> 0) then
  begin
    //�������� �� ICQ ���������
  	if (PacketInfo.DataBuf[1] = #$2a) then
    begin
    	Inc(AIMpckCount); // ����������� ������� �������
      ProcessICQPacket(PacketInfo);
      exit;
    end;

    //�������� �� MRA ���������
    Move(PacketInfo.DataBuf[1],magic,4);
    if magic=$DEADBEEF then
    begin
    	Inc(MRApckCount);
      ProcessMRAPacket(PacketInfo);
      exit;
    end;

    //�������� �� VK ��������� "HTTP" = 48 54 64 50h
    if (PacketInfo.PortSrc=80) or (PacketInfo.PortDest=80) then
    begin
			//mmo1.Lines.Add(LogDataWrapper(PacketInfo));
      //ConvertHTTP (@PacketInfo.DataBuf);
      Proc80(PacketInfo);
    end;
  end;

end;
procedure TfrmMain.Start;
var
  i: integer;
  PathToExe:String;
  AdapterIPList: TStringList;
  AdapterMaskList: TStringList;
  AdapterBcastList: TStringList;
begin
    //��������� ������ �� �������
    if FSettings.InterfaceName='0' then
    begin
      if frmAdapterSelect.ShowModal = mrCancel then
      begin
        Application.Terminate;
        Exit;
      end;

      //��������� ���������
      FSettings.InterfaceName:=frmAdapterSelect.SelAdapterName;
      FSettings.InterfaceDesc:=frmAdapterSelect.SelAdapterDesc;
      PathToExe:=ExtractFileDir(ParamStr(0));
      FSettings.SaveToINI(PathToExe+'\'+SETTINGS_FILENAME);

      FreeAndNil(frmAdapterSelect);
    end;

     // ������ �������, ������� ����� �������
     MonitorPcap.MonAdapter:=AnsiString(FSettings.InterfaceName);
    // ������� ���������� �������
    AdapterIPList:= TStringList.Create;
    AdapterMaskList:= TStringList.Create;
    AdapterBcastList:= TStringList.Create;

    // ���������� IP
    i:=MonitorPcap.GetIPAddresses(MonitorPcap.MonAdapter, AdapterIPList,AdapterMaskList, AdapterBcastList);

    if i > 0 then
    begin
      // �������� ������ IP ����� � ����� � ������.
      MonitorPcap.Addr := AdapterIPList[0];
      MonitorPcap.AddrMask := AdapterMaskList[0];
    end;

    // ������ �������� ��������
    MonitorPcap.IgnoreData := false;
    MonitorPcap.IgnoreLAN := false;
    MonitorPcap.IgnoreNonIP := false;
    MonitorPcap.Promiscuous := true;
    MonitorPcap.ClearIgnoreIP;
    // �����������
    MonitorPcap.StartMonitor;

    if NOT MonitorPcap.Connected then
    begin
      // ���� �������� ������� ������, �� ������� � ���
      FLog.Add('Error:'+MonitorPcap.LastError);
      Application.Terminate;
    end;

    // ������� � ���
    FLog.Add('Capture Started - '+FSettings.InterfaceDesc+' on '+MonitorPcap.Addr);

    // ���� ��� ������ �������, �� ������� - �������.
    MonStarted:= true;

    // �������� ������
    tmrCounter.Enabled := true;
end;
procedure TfrmMain.tmrCounterTimer(Sender: TObject);
begin
  lbCounter.Caption := inttostr(MonitorPcap.TotRecvPackets + MonitorPcap.TotSendPackets);
  lbAIMCounter.Caption := inttostr(AIMpckCount);
  lblMRACounter.Caption := inttostr(MRApckCount);
  lblVKCounter.Caption:=IntToStr(VKpckCount);
end;

end.
