
#ifndef _drvdef_H_
#define _drvdef_H_
#include <ntddk.h>

#include <windef.h>

#define INITCODE code_seg("INIT") 

#define PAGECODE code_seg("PAGE")

//For controlcodes
#include "controlcode.h"


//function declaration
typedef NTSTATUS (* PNtTerminateProcess)(
	IN HANDLE               ProcessHandle OPTIONAL,
	IN NTSTATUS             ExitStatus);
PNtTerminateProcess InitialNtTerminateProcessAddress;

typedef NTSTATUS (* PNtOpenProcess) (
	__out PHANDLE ProcessHandle,
	__in ACCESS_MASK DesiredAccess,
	__in POBJECT_ATTRIBUTES ObjectAttributes,
	__in_opt PCLIENT_ID ClientId
	);

PNtOpenProcess InitialNtOpenProcessAddress;

void Driver_Unload(PDRIVER_OBJECT pDrv);

NTSTATUS CreateDevice(IN PDRIVER_OBJECT pDriverObject);

NTSTATUS HookedNtTerminateProcess(
	IN HANDLE               ProcessHandle OPTIONAL,
	IN NTSTATUS             ExitStatus);

NTSTATUS HookedNtOpenProcess(
	__out PHANDLE ProcessHandle,
	__in ACCESS_MASK DesiredAccess,
	__in POBJECT_ATTRIBUTES ObjectAttributes,
	__in_opt PCLIENT_ID ClientId
	);

void GetNtGDT();

NTSTATUS DispatchRoutine_Close(IN PDEVICE_OBJECT pDevobj,IN PIRP pIrp);

NTSTATUS DispatchRoutine_Create(IN PDEVICE_OBJECT pDevobj,IN PIRP pIrp);

NTSTATUS DispatchRoutine_Read(IN PDEVICE_OBJECT pDevobj,IN PIRP pIrp);

NTSTATUS DispatchRoutine_Device_Control(IN PDEVICE_OBJECT pDevobj,IN PIRP pIrp);

NTSTATUS DispatchRoutine_Write(IN PDEVICE_OBJECT pDevobj,IN PIRP pIrp);

void SSDT_UNHOOK_ALL();

//KeServiceDescriptorTable
typedef struct _ServiceDescriptorTable {
	PVOID ServiceTableBase; 
	PVOID ServiceCounterTable;
	unsigned int NumberOfServices;
	PVOID ParamTableBase;
} *PServiceDescriptorTable;

extern PServiceDescriptorTable KeServiceDescriptorTable;

typedef struct _Hook_Entry {
	ULONG NtIndex;
	ULONG InitialAddress;
	ULONG HookedAddress;
} HookEntry, *PHookEntry;

int SSDT_HOOK_NUMBER = 0;

int Protect_PID_Number = 0;

HookEntry Global_Hook_Entry[255];

DWORD Global_Protect_PID_Table[255];
#endif