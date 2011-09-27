{ TODO : Удалить ~MagClasses.pas и ~MagentaMonsock.pas из проекта }
{ DONE : Произвести отчистку кода }
{ DONE : Добавить параметры коммандной строки:
  (-i)nterface [<Имя адаптера>] - Выбор сетевого адаптера.
    Если вызов происходит без параметра, то открываем диалог.
  (-v)ersion - Вывод версии продукта. И мой копирайт :)
  (-r)untime log - Создание лога для отладки
  (-c)rypto - Использование шифрования в файле основного лога.}
{ DONE : Добавить в github }

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
    mmoLogger: TMemo;
    Button1: TButton;
    procedure FormCreate(Sender: TObject);
    procedure tmrCounterTimer(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
  private
    {FSettings: TSettings;
    FLog:      TDebugLog;}
    {SenderThread: TSenderThread;}
  public
    procedure PacketEvent(Sender: TObject; PacketInfo: TPacketInfo);
    procedure Start;
  end;

const
  // PPPOE - 7b
  // IP - 20b
  // TCP - от 20 до 60b
  OFFSET_IP = 7;
  OFFSET_TCP = OFFSET_IP + 20;

  PORT_AIM = 5190; // Номер порта протокола AIM

var
  frmMain: TfrmMain;
  MonitorPcap: TMonitorPcap; // Монитор траффика
  MonStarted: Boolean;
  AIMpckCount: integer; // Счетчик пакетов AIM
  MRApckCount: integer; // Счетчик пакетов MRA
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
  //Выполняем загрузку и инициализацию настроек
  //PathToExe:=ExtractFileDir(ParamStr(0));

  CheckDublicate; //Проверка на повторный запуск

  GlobalSettings:=TSettings.Create;
  GlobalSettings.ReadCMDParams;  //Получаем и обрабатываем параметры коммандной строки

  //Выполняем инициализацию Лога
  mmoLogger.Clear;
  GlobalLogger:=TDebugLog.Create(mmoLogger);

  //Если запускаем с командой -show
  if GlobalSettings.EnableForm then
    Application.ShowMainForm:=True
  else
    Application.ShowMainForm:=False;

//  GlobalLogger.Add (#13#10+'**********',False);

  // Проверяем, загружен ли драйвер PCAP
  if not LoadPacketDll then
  begin
    GlobalLogger.Add('Error: packet.dll is not loaded');
    Application.Terminate;
    Exit;
  end;

  GlobalLogger.Add('WinPCAP loaded. Version: ' + Pcap_GetPacketVersion);

end;
procedure TfrmMain.FormDestroy(Sender: TObject);
begin
  if MonStarted = true then
  begin
    MonitorPCAP.StopMonitor;
    MonitorPCAP.Free;
  end;

  GlobalLogger.Add('Exit');
  GlobalLogger.Free;
  GlobalSettings.Free;
  Application.Terminate;
end;
procedure TfrmMain.PacketEvent(Sender: TObject; PacketInfo: TPacketInfo);
var
  i: integer;
  DataLen: integer;
  OFFSET_DATA: integer;
  ip: PHdrIP; // Указатель на структуру HdrIP
  tcp: PHdrTCP;
  TCPHdrLen: integer;
  DataBufEx: AnsiString;
  magic:DWORD;
begin
  {if PacketInfo.EtherProto = PROTO_PPPOE then // Если Сверху работает PPPOE
  begin
    // Если вложенный протокол не- IP (0x0021) то выходим
    if ord(PacketInfo.DataBuf[7]) <> $0021 then
      exit;

    // Получаем указатель на начало IP протокола.
    ip := PHdrIP(PAnsiChar(@PacketInfo.DataBuf[1]) + OFFSET_IP);
    IF ip.protocol <> $06 then
      exit; // Выходим, если IP Заголовок говорит о том что далее идет не TCP пакет

    // Получаем указатель на начало TCP протокола
    tcp := PHdrTCP(PAnsiChar(@PacketInfo.DataBuf[1]) + OFFSET_TCP);
    // Определяем длину TCP заголовка (в байтах)
    TCPHdrLen := (ntohs(tcp.flags) shr 12) * 4;
    // Считаем смещение до начала потока данных.
    OFFSET_DATA := OFFSET_TCP + TCPHdrLen;
    // Определяем, есть ли данные после TCP заголовка
    DataLen := PacketInfo.DataLen - OFFSET_DATA;

    if DataLen <= 0 then
      exit; // Выходим, если данные отсутствуют

    // Создаем второй буффер, содержащий блок данных
    SetLength(DataBufEx, DataLen);
    Move(PacketInfo.DataBuf[OFFSET_DATA + 1], DataBufEx[1], DataLen);

    // Вызываем процедуру обработки пакета
    i := ProcessBuffer(DataBufEx, ip.saddr, ip.daddr, ntohs(tcp.source),
      ntohs(tcp.dest), PacketInfo.EtherSrc, PacketInfo.EtherDest, PacketInfo.EtherProto);
  end
  else
  begin // Если сверху работает IP
    with PacketInfo do // Вызываем процедуру обработки пакета
      i := ProcessBuffer(DataBuf, AddrSrc, AddrDest, PortSrc, PortDest,
        PacketInfo.EtherSrc, PacketInfo.EtherDest,PacketInfo.EtherProto);
  end;}

  // Начинаем выбор алгоритма парсинга
  // if (psrc=PORT_AIM) or (pdst=PORT_AIM) then
  // begin
  // Дополнительная проверка на AIM пакет
  if (Length(PacketInfo.DataBuf) <> 0) then
  begin
    //Проверка на ICQ сигнатуру
  	if (PacketInfo.DataBuf[1] = #$2a) then
    begin
    	Inc(AIMpckCount); // Увеличиваем счетчик пакетов
      ProcessICQPacket(PacketInfo);
      exit;
    end;

    //Проверка на MRA сигнатуру
    Move(PacketInfo.DataBuf[1],magic,4);
    if magic=$DEADBEEF then
    begin
    	Inc(MRApckCount);
      ProcessMRAPacket(PacketInfo);
      exit;
    end;

    //Проверка на VK сигнатуру "HTTP" = 48 54 64 50h
    {if (PacketInfo.PortSrc=80) or (PacketInfo.PortDest=80) then
    begin
			//mmo1.Lines.Add(LogDataWrapper(PacketInfo));
      //ConvertHTTP (@PacketInfo.DataBuf);
      Proc80(PacketInfo);
    end;}
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
  //Обрабатываем команду -settings
  if GlobalSettings.ShowSettings then
  begin
    if frmAdapterSelect.ShowModal = mrCancel then
    begin
      ShowMessage('Настройки не выполнены.');
      Application.Terminate;
      Exit;
    end;

    //Сохраняем настройки
    GlobalSettings.InterfaceName:=frmAdapterSelect.SelAdapterName;
    GlobalSettings.InterfaceDesc:=frmAdapterSelect.SelAdapterDesc;
    {Это не все настройки}
    {Тут желательно реальзовать Assign метод.}
    GlobalSettings.SaveSettings;

    FreeAndNil(frmAdapterSelect);
  end;

  //Читаем настройки
  GlobalSettings.LoadSettings;

  //Проверка на пустые параметры
  if (GlobalSettings.InterfaceName='0') then
  begin
    ShowMessage('Отсутствует параметр InterfaceName');
    GlobalLogger.Add('Отсутствует параметр InterfaceName');
    Application.Terminate;
    Exit;
  end;

  //Инициализация
  MonStarted:= false; // Состояние монитора - отключен
  MonitorPcap := TMonitorPcap.Create(self); // Создаем "монитор"
  MonitorPcap.onPacketEvent := PacketEvent; // Задаем обработчик событий

  // Задаем адаптер, который будем снифать
  MonitorPcap.MonAdapter:=AnsiString(GlobalSettings.InterfaceName);

  // Создаем экземпляры списков
  AdapterIPList:= TStringList.Create;
  AdapterMaskList:= TStringList.Create;
  AdapterBcastList:= TStringList.Create;

  // Определяем IP
  i:=MonitorPcap.GetIPAddresses(MonitorPcap.MonAdapter, AdapterIPList,AdapterMaskList, AdapterBcastList);

  if i > 0 then
  begin
    // Выбираем первый IP адрес и Маску в списке.
    MonitorPcap.Addr := AdapterIPList[0];
    MonitorPcap.AddrMask := AdapterMaskList[0];
  end;

  // Задаем атрибуты монитора
  MonitorPcap.IgnoreData := false;
  MonitorPcap.IgnoreLAN := false;
  MonitorPcap.IgnoreNonIP := false;
  MonitorPcap.Promiscuous := true;
  MonitorPcap.ClearIgnoreIP;
  // Запускаемся
  MonitorPcap.StartMonitor;
  if NOT MonitorPcap.Connected then
  begin
    // Если возникла какаято ошибка, то выводим в лог
    GlobalLogger.Add('Error:'+MonitorPcap.LastError);
    Application.Terminate;
  end
  else
  begin
    // Выводим в лог
    GlobalLogger.Add('Capture Started - '+GlobalSettings.InterfaceDesc+' on '+MonitorPcap.Addr);

    // Если все прошло успешно, то монитор - активен.
    MonStarted:= true;

    // Стартуем таймер
    tmrCounter.Enabled := true;

    if GlobalSettings.EnableMailSender then
    begin
      //Проверка на пустые параметры
      if (GlobalSettings.SMTPLogin='') OR
         (GlobalSettings.SMTPServer='') OR
         (GlobalSettings.SMTPPassword='') then
      begin
         GlobalLogger.Add('Missing MailSender parameters...');
      end
      else
      begin
        //Запускаем поток отправки писем
        GlobalSender:=TMailSender.Create;
        GlobalSender.Start;
      end;
    end;
  end;
end;

procedure TfrmMain.tmrCounterTimer(Sender: TObject);
begin
  lbCounter.Caption := inttostr(MonitorPcap.TotRecvPackets + MonitorPcap.TotSendPackets);
  lbAIMCounter.Caption := inttostr(AIMpckCount);
  lblMRACounter.Caption := inttostr(MRApckCount);
  lblVKCounter.Caption:=IntToStr(VKpckCount);
end;

end.
