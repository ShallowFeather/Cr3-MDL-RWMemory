#include <ntifs.h>
#include <windef.h>
#include <intrin.h>
#include "global.h"
#define printfs(x, ...) DbgPrintEx(0, 0, x, __VA_ARGS__)

NTKERNELAPI NTSTATUS IoCreateDriver(PUNICODE_STRING DriverName, PDRIVER_INITIALIZE InitializationFunction);


#define init_code CTL_CODE(FILE_DEVICE_UNKNOWN, 0x775, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define read_code CTL_CODE(FILE_DEVICE_UNKNOWN, 0x776, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define write_code CTL_CODE(FILE_DEVICE_UNKNOWN, 0x777, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define base_code CTL_CODE(FILE_DEVICE_UNKNOWN, 0x778, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

typedef struct info_t {
	HANDLE target_pid;
	void* target_address;
	PBYTE buffer_address;
	SIZE_T Size;
	SIZE_T return_size;
	void* base;
} UserData, * PUserData;

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
	pDTB = CheckAddressVal((UCHAR*)Process + 0x28);
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

VOID DeAttach(IN ULONG64 OldCr3) {
	_disable();
	__writecr3(OldCr3);
	_enable();

}

ULONG64 get_module_base_x64(PEPROCESS proc) {
	return (ULONG64)PsGetProcessSectionBaseAddress(proc);
}

NTSTATUS ctl_io(PDEVICE_OBJECT device_obj, PIRP irp) {
	UNREFERENCED_PARAMETER(device_obj);

	static PEPROCESS Process;

	irp->IoStatus.Information = sizeof(UserData);
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
	PUserData Buffer = (PUserData)irp->AssociatedIrp.SystemBuffer;
	DbgPrint("IOCTL\n");

	if (stack) { //add error checking
		if (Buffer && sizeof(*Buffer) >= sizeof(UserData)) {
			ULONG ctl_code = stack->Parameters.DeviceIoControl.IoControlCode;
			if (ctl_code == init_code)
				PsLookupProcessByProcessId(Buffer->target_pid, &Process);

			else if (ctl_code == read_code) {
				DbgPrint("READ\n");
				PBYTE Temp = ExAllocatePool(PagedPool, Buffer->Size);
				if (Temp == NULL)
				{
					printfs("[Mdl] : read ExAllocatePool FAIL");
					ObDereferenceObject(Process);
					return;
				}

				ULONG64 OldCr3 = Attach(Process);

				ProbeForRead((PVOID)Buffer->target_address, Buffer->Size, 1);
				RtlCopyMemory(Temp, (PVOID)Buffer->target_address, Buffer->Size);

				DeAttach(OldCr3);

				RtlCopyMemory(Buffer->buffer_address, Temp, Buffer->Size);
				DbgPrint("%d\n", *Buffer->buffer_address);
				ExFreePool(Temp);
			}

			else if (ctl_code == write_code) {
				DbgPrint("WRITE\n");

				PBYTE Temp = ExAllocatePool(PagedPool, Buffer->Size);
				if (Temp == NULL)
				{
					printfs("[Mdl] : write ExAllocatePool FAIL");
					ObDereferenceObject(Process);
					return;
				}

				for (DWORD i = 0; i < Buffer->Size; i++) Temp[i] = Buffer->buffer_address[i];

				ULONG64 OldCr3 = Attach(Process);

				PMDL Mdl = IoAllocateMdl((PVOID)Buffer->target_address, Buffer->Size, FALSE, FALSE, NULL);
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
				DeAttach(OldCr3);
			}
			else if (ctl_code == base_code) {
				PEPROCESS process = NULL;
				NTSTATUS Status = PsLookupProcessByProcessId((HANDLE)Buffer->target_pid, &process);
				Buffer->base = (PVOID)get_module_base_x64(process);
			}
			irp->IoStatus.Information = sizeof(UserData);

		}
	}

	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS unsupported_io(PDEVICE_OBJECT device_obj, PIRP irp) {
	UNREFERENCED_PARAMETER(device_obj);

	irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return irp->IoStatus.Status;
}

NTSTATUS create_io(PDEVICE_OBJECT device_obj, PIRP irp) {
	UNREFERENCED_PARAMETER(device_obj);

	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return irp->IoStatus.Status;
}

NTSTATUS close_io(PDEVICE_OBJECT device_obj, PIRP irp) {
	UNREFERENCED_PARAMETER(device_obj);

	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return irp->IoStatus.Status;
}

NTSTATUS real_main(PDRIVER_OBJECT driver_obj, PUNICODE_STRING registery_path) {
	UNREFERENCED_PARAMETER(registery_path);

	UNICODE_STRING dev_name, sym_link;
	PDEVICE_OBJECT dev_obj;

	RtlInitUnicodeString(&dev_name, L"\\Device\\cartidriver");
	auto status = IoCreateDevice(driver_obj, 0, &dev_name, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &dev_obj);
	if (status != STATUS_SUCCESS) return status;

	RtlInitUnicodeString(&sym_link, L"\\DosDevices\\cartidriver");
	status = IoCreateSymbolicLink(&sym_link, &dev_name);
	if (status != STATUS_SUCCESS) return status;

	SetFlag(dev_obj->Flags, DO_BUFFERED_IO);

	for (int t = 0; t <= IRP_MJ_MAXIMUM_FUNCTION; t++)
		driver_obj->MajorFunction[t] = unsupported_io;

	driver_obj->MajorFunction[IRP_MJ_CREATE] = create_io;
	driver_obj->MajorFunction[IRP_MJ_CLOSE] = close_io;
	driver_obj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = ctl_io;
	driver_obj->DriverUnload = NULL;

	ClearFlag(dev_obj->Flags, DO_DEVICE_INITIALIZING);
	return status;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driver_obj, PUNICODE_STRING registery_path) {
	UNREFERENCED_PARAMETER(driver_obj);
	UNREFERENCED_PARAMETER(registery_path);

	UNICODE_STRING  drv_name;
	RtlInitUnicodeString(&drv_name, L"\\Driver\\cartidriver");
	IoCreateDriver(&drv_name, &real_main);
	DbgPrint("LOAD\n");
	return STATUS_SUCCESS;
}
