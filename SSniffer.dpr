program SSniffer;
{
TODO:
  - ������� ~MagClasses.pas � ~MagentaMonsock.pas �� �������
  - ���������� �������� ����
  - �������� ��������� ���������� ������
    -- (-i)nterface [<��� ��������>] - ����� �������� ��������.
      ���� ����� ���������� ��� ���������, �� ��������� ������.
    -- (-v)ersion - ����� ������ ��������. � ��� �������� :)
    -- (-r)untime log - �������� ���� ��� �������
    -- (-c)rypto - ������������� ���������� � ����� ��������� ����.
  - �������� � github
  - ������������ ������ MagentaPCap � �������

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
    ���� ��� ���������� �����.
    ������� � ������ ����� ��������� ����������� �� ������: osmenog@gmail.com
  *)
  Application.Initialize;
  Application.MainFormOnTaskbar:= True;
  {
    ��� ���� ��������� �������� �� ��������� ������
  }
  Application.Title := 'SSniffer';
  Application.CreateForm(TfrmMain, frmMain);
  Application.CreateForm(TfrmAdapterSelect, frmAdapterSelect);
  frmMain.Start;
  Application.Run;
end.
