unit SClasses;

interface

uses Dialogs,Windows,SysUtils,IniFiles;
const
  SETTINGS_FILENAME='config.ini';

type
  TSettings = class (TObject)
    private
      FCMD_EnableLog:       Boolean; //  [-l]
      FCMD_ShowWindow:      Boolean; //  [-s]
      FCMD_SelectInterface: Boolean; //  [-i]
      {----------------------------}
      FInterfaceName:       String;
      FInterfaceDesc:       String;

    public
      constructor Create;
      destructor  Destroy;
      procedure   LoadFromINI (filename:string);
      procedure   SaveToINI (filename:string);
      function    IsDublicate: Boolean;
      procedure   CheckDublicate;
      procedure   ReadCMDParams;

      property CMD_EnableLog:Boolean       read FCMD_EnableLog;
      property CMD_ShowWindow:Boolean      read FCMD_ShowWindow;
      property CMD_SelectInterface:Boolean read FCMD_SelectInterface;

      property InterfaceName:String read FInterfaceName;
      property InterfaceDesc:String read FInterfaceDesc;
  end;
  TDebugLog = class
    private
      FFileName: String;
      FEnable: Boolean;
      FMsgBoxEnable: Boolean;
      procedure WriteLine (Msg:string);
    public
      constructor Create(FileName:string='debug.log');
      procedure Add (Msg:string;PrintDate:Boolean=True);
      procedure ApplySettings (const S:TSettings);
  end;

implementation

//TSettings
constructor TSettings.Create;
begin
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
procedure TSettings.LoadFromINI(filename: string);
var
  Ini:TIniFile;
begin
  //if FileExists(filename) then
  //begin
    Ini:=TIniFile.Create(filename);
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
procedure TSettings.SaveToINI(filename: string);
var
  Ini:TIniFile;
begin
    Ini:=TIniFile.Create(filename);
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
      if ParamStr(i)='/?' then
      begin
        ShowMessage('This is help');
        Exit;
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
constructor TDebugLog.Create(FileName: string);
begin
  {
    Сюда нужно включить проверку на возможность создания файла.
  }
  FFileName:=FileName;
  FEnable:=True;
  FMsgBoxEnable:=False;
end;
procedure TDebugLog.Add(Msg: string;PrintDate:Boolean);
begin
  if FEnable then
  begin
    if PrintDate then
      WriteLine(DateTimeToStr(Now)+' '+Msg)
    else
      WriteLine(Msg);
  end;
end;
procedure TDebugLog.WriteLine(Msg: string);
//Пишем служебную инфу в "Рантайм лог"
var
  i:integer;
  F:TextFile;
  FullPath:string;
begin
  AssignFile(F,FFileName);
  try
		if not FileExists(FFileName) then Rewrite(F) else Append(F);
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
procedure TDebugLog.ApplySettings(const S: TSettings);
begin
  if S.FCMD_EnableLog then FEnable:=True else FEnable:=False;
  if S.FCMD_ShowWindow then FMsgBoxEnable:=True else FMsgBoxEnable:=False;
end;

{ end of TDebugLog }
end.
