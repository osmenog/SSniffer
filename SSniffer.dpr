program SSniffer;
{
TODO:
  - Удалить ~MagClasses.pas и ~MagentaMonsock.pas из проекта
  - Произвести отчистку кода
  - Добавить параметры коммандной строки
    -- (-i)nterface [<Имя адаптера>] - Выбор сетевого адаптера.
      Если вызов происходит без параметра, то открываем диалог.
    -- (-v)ersion - Вывод версии продукта. И мой копирайт :)
    -- (-r)untime log - Создание лога для отладки
    -- (-c)rypto - Использование шифрования в файле основного лога.
  - Добавить в github
  - Присоеденить модули MagentaPCap к проекту

}



uses
  Forms,
  Dialogs,
  SysUtils,
  Windows,
  SSUtils in 'units\SSUtils.pas',
  SSBox in 'units\SSBox.pas',
  SClasses in 'units\SClasses.pas',
  MagClasses in 'units\Magenta\MagClasses.pas',
  MagentaBpf in 'units\Magenta\MagentaBpf.pas',
  MagentaMonpcap in 'units\Magenta\MagentaMonpcap.pas',
  MagentaNdis_def in 'units\Magenta\MagentaNdis_def.pas',
  MagentaPacket32 in 'units\Magenta\MagentaPacket32.pas',
  MagentaPackhdrs in 'units\Magenta\MagentaPackhdrs.pas',
  MagentaPcap in 'units\Magenta\MagentaPcap.pas',
  magsubs1 in 'units\Magenta\magsubs1.pas',
  ICQparser in 'units\Dissectors\ICQparser.pas',
  MRAParcer in 'units\Dissectors\MRAParcer.pas',
  MainUnit in 'Forms\MainUnit.pas' {frmMain},
  AdaptorSelector in 'Forms\AdaptorSelector.pas' {frmAdapterSelect};

begin
  (*
    Этот код редкостное гавно.
    Поэтому я всегда готов выслушать предложения по адресу: osmenog@gmail.com
  *)
  Application.Initialize;
  Application.MainFormOnTaskbar:= True;
  {
    Тут надо выполнить проверку на повторный запуск
  }
  Application.Title := 'SSniffer';
  Application.CreateForm(TfrmMain, frmMain);
  Application.CreateForm(TfrmAdapterSelect, frmAdapterSelect);
  frmMain.Start;
  Application.Run;
end.
