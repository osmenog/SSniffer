unit AdaptorSelector;

interface

uses
  Windows, Messages, SysUtils, Variants, Classes, Graphics, Controls, Forms,
  Dialogs,MagentaPackHdrs,MagentaMonpcap, StdCtrls;

type
  TfrmAdapterSelect = class(TForm)
    grp1: TGroupBox;
    btnSave: TButton;
    cbAdapterList: TComboBox;
    procedure btnSaveClick(Sender: TObject);
    procedure FormCreate(Sender: TObject);
    procedure FormClose(Sender: TObject; var Action: TCloseAction);
  private
    AdapterListName: TStringList;
    AdapterListDesc: TStringList;
  public
    { Public declarations }
    SelAdapterName: string;
    SelAdapterDesc: string;
  end;

var
  frmAdapterSelect: TfrmAdapterSelect;

implementation

{$R *.dfm}

procedure TfrmAdapterSelect.btnSaveClick(Sender: TObject);
begin
	SelAdapterName:=AdapterListName[cbAdapterList.ItemIndex];
  SelAdapterDesc:=AdapterListDesc[cbAdapterList.ItemIndex];
	frmAdapterSelect.Close;
end;

procedure TfrmAdapterSelect.FormClose(Sender: TObject;
  var Action: TCloseAction);
begin
	AdapterListDesc.Free;
  AdapterListName.Free;
end;

procedure TfrmAdapterSelect.FormCreate(Sender: TObject);
var
	Mon:TMonitorPcap;
  i:integer;
  tmp:TStringList;
begin
  cbAdapterList.Clear;
  AdapterListDesc:=TStringList.Create;
  AdapterListName:=TStringList.Create;
  Mon:=TMonitorPcap.Create(nil);
  for i := 0 to Mon.AdapterNameList.Count-1 do
  begin
    AdapterListName.Add(Mon.AdapterNameList[i]);
		AdapterListDesc.Add(Mon.AdapterDescList[i]);
  end;
  cbAdapterList.Items.Assign (AdapterListDesc);
  Mon.Free;
  cbAdapterList.ItemIndex:=0;
end;

end.
