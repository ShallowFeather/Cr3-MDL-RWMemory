#include <ntifs.h>
#include <windef.h>
#include <intrin.h>

/* ���Ը������� */
#define printfs(x, ...) DbgPrintEx(0, 0, x, __VA_ARGS__)

/* ��ȡ�ڴ� */
#define Mdl_Read CTL_CODE(FILE_DEVICE_UNKNOWN,0x800,METHOD_BUFFERED,FILE_ALL_ACCESS)

/* д���ڴ� */
#define Mdl_Write CTL_CODE(FILE_DEVICE_UNKNOWN,0x801,METHOD_BUFFERED,FILE_ALL_ACCESS)

/* ������Ϣ�Ľṹ */
typedef struct _UserData
{
	DWORD Pid;							//Ҫ��д�Ľ���ID
	DWORD64 Address;				//Ҫ��д�ĵ�ַ
	DWORD Size;							//��д����
	PBYTE Data;								//Ҫ��д������
}UserData, * PUserData;

#define DIRECTORY_TABLE_BASE 0x028
#pragma intrinsic(_disable)
#pragma intrinsic(_enable)
NTKERNELAPI NTSTATUS PsLookupProcessByProcessId(HANDLE ProcessId, PEPROCESS
	* Process);
NTKERNELAPI CHAR* PsGetProcessImageFileName(PEPROCESS Process);
// 关闭写保护
KIRQL Open()
{
	KIRQL irql = KeRaiseIrqlToDpcLevel();
	UINT64 cr0 = __readcr0();
	cr0 &= 0xfffffffffffeffff;
	__writecr0(cr0);
	_disable();
	return irql;
}
// 开启写保护
void Close(KIRQL irql)
{
	UINT64 cr0 = __readcr0();
	cr0 |= 0x10000;
	_enable();
	__writecr0(cr0);
	KeLowerIrql(irql);
}
// 检查内存
ULONG64 CheckAddressVal(PVOID p)
{
	if (MmIsAddressValid(p) == FALSE)
		return 0;
	return *(PULONG64)p;
}

ULONG64 Attach(IN PEPROCESS Process) {
	ULONG64 pDTB = 0, OldCr3 = 0, vAddr = 0;
	pDTB = CheckAddressVal((UCHAR*)Process + DIRECTORY_TABLE_BASE);
	if (pDTB == 0)
	{
		return FALSE;
	}
	_disable();
	OldCr3 = __readcr3();
	__writecr3(pDTB);
	_enable();
	return OldCr3;
}

VOID Deattach(IN ULONG64 OldCr3) {
	_disable();
	__writecr3(OldCr3);
	_enable();

}

// {F90B1129-715C-4F84-A069-FEE12E2AFB48}
UNICODE_STRING DeviceName = RTL_CONSTANT_STRING(L"\\Device\\SFeather");
UNICODE_STRING DeviceLink = RTL_CONSTANT_STRING(L"\\??\\SFeather");

//��ȡ�ڴ�
VOID MdlReadProcessMemory(PUserData Buffer)
{
	//��Ŀ�����
	PEPROCESS Process = NULL;
	NTSTATUS Status = PsLookupProcessByProcessId((HANDLE)Buffer->Pid, &Process);
	if (!NT_SUCCESS(Status))
	{
		printfs("[Mdl] : read PsLookupProcessByProcessId FAIL");
		return;
	}

	//�����ڴ�ռ�
	PBYTE Temp = ExAllocatePool(PagedPool, Buffer->Size);
	if (Temp == NULL)
	{
		printfs("[Mdl] : read ExAllocatePool FAIL");
		ObDereferenceObject(Process);
		return;
	}

	//���ӽ���
	ULONG64 OldCr3 = Attach(Process);

	//�����ڴ�
	ProbeForRead((PVOID)Buffer->Address, Buffer->Size, 1);

	//�����ڴ�
	RtlCopyMemory(Temp, (PVOID)Buffer->Address, Buffer->Size);

	//�������
	ObDereferenceObject(Process);

	//��������
	Deattach(OldCr3);

	//���Ƶ����ǵĻ�����
	RtlCopyMemory(Buffer->Data, Temp, Buffer->Size);

	//�ͷ��ڴ�
	ExFreePool(Temp);
}

//д���ڴ�
VOID MdlWriteProcessMemory(PUserData Buffer)
{
	//��Ŀ�����
	PEPROCESS Process = NULL;
	NTSTATUS Status = PsLookupProcessByProcessId((HANDLE)Buffer->Pid, &Process);
	if (!NT_SUCCESS(Status))
	{
		printfs("[Mdl] : write PsLookupProcessByProcessId FAIL");
		return;
	}

	//�����ڴ�ռ�
	PBYTE Temp = ExAllocatePool(PagedPool, Buffer->Size);
	if (Temp == NULL)
	{
		printfs("[Mdl] : write ExAllocatePool FAIL");
		ObDereferenceObject(Process);
		return;
	}

	//�����ڴ�����
	for (DWORD i = 0; i < Buffer->Size; i++) Temp[i] = Buffer->Data[i];

	//���ӽ���
	ULONG64 OldCr3 = Attach(Process);

	//����MDL
	PMDL Mdl = IoAllocateMdl((PVOID)Buffer->Address, Buffer->Size, FALSE, FALSE, NULL);
	if (Mdl == NULL)
	{
		printfs("[Mdl] : IoAllocateMdl Fail");
		ExFreePool(Temp);
		ObDereferenceObject(Process);
		return;
	}

	//��������ҳ��
	MmBuildMdlForNonPagedPool(Mdl);

	//����ҳ��
	PBYTE ChangeData = MmMapLockedPages(Mdl, KernelMode);

	//�����ڴ�
	if (ChangeData) RtlCopyMemory(ChangeData, Temp, Buffer->Size);

	//�ͷ�����
	IoFreeMdl(Mdl);
	ExFreePool(Temp);
	Deattach(OldCr3);
	ObDereferenceObject(Process);
}

//������ǲ����
NTSTATUS DriverIoctl(PDEVICE_OBJECT Device, PIRP pirp)
{
	//δ����
	UNREFERENCED_PARAMETER(Device);

	//��ȡ��ջ
	PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(pirp);

	//��ȡ������
	ULONG Code = Stack->Parameters.DeviceIoControl.IoControlCode;

	if (Stack->MajorFunction == IRP_MJ_DEVICE_CONTROL)
	{
		//��ȡ����ָ��
		PUserData Buffer = pirp->AssociatedIrp.SystemBuffer;
		printfs("[Mdl] : PID:%d  Addr ַ:%x  Size:%d", Buffer->Pid, Buffer->Address, Buffer->Size);

		if (Code == Mdl_Read) MdlReadProcessMemory(Buffer); //��ȡ�ڴ�
		if (Code == Mdl_Write) MdlWriteProcessMemory(Buffer);//д���ڴ�

		pirp->IoStatus.Information = sizeof(UserData);
	}
	else pirp->IoStatus.Information = 0;

	//���IO
	pirp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(pirp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

//����ж�غ���
VOID DriverUnload(PDRIVER_OBJECT object)
{
	if (object->DeviceObject)
	{
		IoDeleteSymbolicLink(&DeviceLink);
		IoDeleteDevice(object->DeviceObject);
	}
	printfs("[Mdl] : Unload");
}

//������ں���
NTSTATUS DriverEntry(PDRIVER_OBJECT object, PUNICODE_STRING reg)
{
	printfs("[Mdl] : LOAD -> %wZ", reg);

	//����ж�غ���
	object->DriverUnload = DriverUnload;

	//�����豸
	PDEVICE_OBJECT Device = NULL;
	NTSTATUS Status = IoCreateDevice(object, sizeof(object->DriverExtension), &DeviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &Device);
	if (!NT_SUCCESS(Status))
	{
		printfs("[Mdl] : IoCreateDevice FAIL");
		return Status;
	}

	//��������
	Status = IoCreateSymbolicLink(&DeviceLink, &DeviceName);
	if (!NT_SUCCESS(Status))
	{
		printfs("[Mdl] : IoCreateSymbolicLink FAIL");
		IoDeleteDevice(Device);
		return Status;
	}

	//������ǲ����
	object->MajorFunction[IRP_MJ_CREATE] = DriverIoctl;
	object->MajorFunction[IRP_MJ_CLOSE] = DriverIoctl;
	object->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverIoctl;

	printfs("[Mdl] : �������سɹ�");
	return STATUS_SUCCESS;
}