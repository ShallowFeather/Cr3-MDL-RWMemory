#include <ntifs.h>
#include <windef.h>
#include <intrin.h>

#define printfs(x, ...) DbgPrintEx(0, 0, x, __VA_ARGS__)

#define Mdl_Read CTL_CODE(FILE_DEVICE_UNKNOWN,0x800,METHOD_BUFFERED,FILE_ALL_ACCESS)

#define Mdl_Write CTL_CODE(FILE_DEVICE_UNKNOWN,0x801,METHOD_BUFFERED,FILE_ALL_ACCESS)

typedef struct _UserData
{
	DWORD Pid;	
	DWORD64 Address;
	DWORD Size;
	PBYTE Data;	
}UserData, * PUserData;

#define DIRECTORY_TABLE_BASE 0x028
#pragma intrinsic(_disable)
#pragma intrinsic(_enable)
NTKERNELAPI NTSTATUS PsLookupProcessByProcessId(HANDLE ProcessId, PEPROCESS
	* Process);
NTKERNELAPI CHAR* PsGetProcessImageFileName(PEPROCESS Process);
KIRQL Open()
{
	KIRQL irql = KeRaiseIrqlToDpcLevel();
	UINT64 cr0 = __readcr0();
	cr0 &= 0xfffffffffffeffff;
	__writecr0(cr0);
	_disable();
	return irql;
}
void Close(KIRQL irql)
{
	UINT64 cr0 = __readcr0();
	cr0 |= 0x10000;
	_enable();
	__writecr0(cr0);
	KeLowerIrql(irql);
}
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

UNICODE_STRING DeviceName = RTL_CONSTANT_STRING(L"\\Device\\SFeather");
UNICODE_STRING DeviceLink = RTL_CONSTANT_STRING(L"\\??\\SFeather");

VOID MdlReadProcessMemory(PUserData Buffer)
{
	PEPROCESS Process = NULL;
	NTSTATUS Status = PsLookupProcessByProcessId((HANDLE)Buffer->Pid, &Process);
	if (!NT_SUCCESS(Status))
	{
		printfs("[Mdl] : read PsLookupProcessByProcessId FAIL");
		return;
	}

	PBYTE Temp = ExAllocatePool(PagedPool, Buffer->Size);
	if (Temp == NULL)
	{
		printfs("[Mdl] : read ExAllocatePool FAIL");
		ObDereferenceObject(Process);
		return;
	}

	ULONG64 OldCr3 = Attach(Process);

	ProbeForRead((PVOID)Buffer->Address, Buffer->Size, 1);

	RtlCopyMemory(Temp, (PVOID)Buffer->Address, Buffer->Size);

	ObDereferenceObject(Process);

	Deattach(OldCr3);

	RtlCopyMemory(Buffer->Data, Temp, Buffer->Size);

	ExFreePool(Temp);
}

VOID MdlWriteProcessMemory(PUserData Buffer)
{
	PEPROCESS Process = NULL;
	NTSTATUS Status = PsLookupProcessByProcessId((HANDLE)Buffer->Pid, &Process);
	if (!NT_SUCCESS(Status))
	{
		printfs("[Mdl] : write PsLookupProcessByProcessId FAIL");
		return;
	}

	PBYTE Temp = ExAllocatePool(PagedPool, Buffer->Size);
	if (Temp == NULL)
	{
		printfs("[Mdl] : write ExAllocatePool FAIL");
		ObDereferenceObject(Process);
		return;
	}

	for (DWORD i = 0; i < Buffer->Size; i++) Temp[i] = Buffer->Data[i];

	ULONG64 OldCr3 = Attach(Process);

	PMDL Mdl = IoAllocateMdl((PVOID)Buffer->Address, Buffer->Size, FALSE, FALSE, NULL);
	if (Mdl == NULL)
	{
		printfs("[Mdl] : IoAllocateMdl Fail");
		ExFreePool(Temp);
		ObDereferenceObject(Process);
		return;
	}

	MmBuildMdlForNonPagedPool(Mdl);

	PBYTE ChangeData = MmMapLockedPages(Mdl, KernelMode);

	if (ChangeData) RtlCopyMemory(ChangeData, Temp, Buffer->Size);

	IoFreeMdl(Mdl);
	ExFreePool(Temp);
	Deattach(OldCr3);
	ObDereferenceObject(Process);
}

NTSTATUS DriverIoctl(PDEVICE_OBJECT Device, PIRP pirp)
{
	UNREFERENCED_PARAMETER(Device);

	PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(pirp);

	ULONG Code = Stack->Parameters.DeviceIoControl.IoControlCode;

	if (Stack->MajorFunction == IRP_MJ_DEVICE_CONTROL)
	{
		PUserData Buffer = pirp->AssociatedIrp.SystemBuffer;
		printfs("[Mdl] : PID:%d  Addr ַ:%x  Size:%d", Buffer->Pid, Buffer->Address, Buffer->Size);

		if (Code == Mdl_Read) MdlReadProcessMemory(Buffer);
		if (Code == Mdl_Write) MdlWriteProcessMemory(Buffer);

		pirp->IoStatus.Information = sizeof(UserData);
	}
	else pirp->IoStatus.Information = 0;

	pirp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(pirp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

VOID DriverUnload(PDRIVER_OBJECT object)
{
	if (object->DeviceObject)
	{
		IoDeleteSymbolicLink(&DeviceLink);
		IoDeleteDevice(object->DeviceObject);
	}
	printfs("[Mdl] : Unload");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT object, PUNICODE_STRING reg)
{
	printfs("[Mdl] : LOAD -> %wZ", reg);

	object->DriverUnload = DriverUnload;

	PDEVICE_OBJECT Device = NULL;
	NTSTATUS Status = IoCreateDevice(object, sizeof(object->DriverExtension), &DeviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &Device);
	if (!NT_SUCCESS(Status))
	{
		printfs("[Mdl] : IoCreateDevice FAIL");
		return Status;
	}

	Status = IoCreateSymbolicLink(&DeviceLink, &DeviceName);
	if (!NT_SUCCESS(Status))
	{
		printfs("[Mdl] : IoCreateSymbolicLink FAIL");
		IoDeleteDevice(Device);
		return Status;
	}

	object->MajorFunction[IRP_MJ_CREATE] = DriverIoctl;
	object->MajorFunction[IRP_MJ_CLOSE] = DriverIoctl;
	object->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverIoctl;

	printfs("[Mdl] : �������سɹ�");
	return STATUS_SUCCESS;
}