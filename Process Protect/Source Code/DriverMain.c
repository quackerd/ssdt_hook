#include "drvdef.h"
#include "nthook.h"

//init code seg. Deleted after using.
#pragma INITCODE

//Driver Entry-like main
NTSTATUS DriverEntry(PDRIVER_OBJECT pDrv,PUNICODE_STRING pCode)
{
	NTSTATUS status;
	//Unload function
	pDrv->DriverUnload=Driver_Unload;
	//Create Device
	status=CreateDevice(pDrv);
	//Dispatch functions - for communication
	pDrv->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchRoutine_Device_Control;
	pDrv->MajorFunction[IRP_MJ_CLOSE] = DispatchRoutine_Close;
	pDrv->MajorFunction[IRP_MJ_WRITE] = DispatchRoutine_Write;
	pDrv->MajorFunction[IRP_MJ_READ] = DispatchRoutine_Read;
	pDrv->MajorFunction[IRP_MJ_CREATE] = DispatchRoutine_Create;
	//print 
	DbgPrint("Driver Successfully Loaded\n");
	//store initial address of NtTerminateProcess
	InitialNtTerminateProcessAddress = (PNtTerminateProcess)GetNtCurrentAddress(NtTerminateProcessIndex);
	//Hook NtTerminateProcess 
	status = Nt_SSDT_Hook(NtTerminateProcessIndex,(ULONG)HookedNtTerminateProcess);
	//Hook NtTerminateProcess 
	InitialNtOpenProcessAddress = (PNtOpenProcess)GetNtCurrentAddress(NtOpenProcessIndex);
	//Hook NtTerminateProcess 
	status = Nt_SSDT_Hook(NtOpenProcessIndex,(ULONG)HookedNtOpenProcess);
	//return 
	return status;
}