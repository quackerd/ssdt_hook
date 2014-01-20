#ifndef _nthook_H_
#define _nthook_H_
#include "drvdef.h"

#include "controlcode.h"

//Function Declaration
ULONG GetNtInitialAddress(UNICODE_STRING FuncName);

ULONG GetNtCurrentAddress(ULONG NtIndex);

BOOL IsProcessProtected(DWORD PID);

NTSTATUS Nt_SSDT_Hook(ULONG NtIndex,ULONG HookedAddress);

NTSTATUS Nt_SSDT_UnHook(ULONG NtIndex,ULONG InitialAddress);

void ClosePageProtection();

void OpenPageProtection();

void Write_SSDT_Hook_Table(HookEntry* Hook_Entry,ULONG NtIndex,ULONG InitialAddress,ULONG HookedAddress);

//PAGE
#pragma PAGECODE

//Used for getting the address of Nt functions
ULONG GetNtInitialAddress(UNICODE_STRING FuncName)
{
	return (ULONG)MmGetSystemRoutineAddress(&FuncName);
}

#pragma PAGECODE

ULONG GetNtCurrentAddress(ULONG NtIndex)
{
	ULONG RTN;
	ULONG _index = NtIndex * 4;

	__asm
	{
		push ecx
		
			mov ecx,KeServiceDescriptorTable
			//get the first term
			mov ecx,[ecx]
		//nth term = base+4n
		add ecx,_index

			mov ecx,[ecx]

		mov RTN,ecx
			pop ecx
	}
	return RTN;
}

#pragma PAGECODE
//the function to hook ssdt table
NTSTATUS Nt_SSDT_Hook(ULONG NtIndex,ULONG HookedAddress)
{
	ULONG _InitialAddress,_HookedAddress;
	ULONG _index = NtIndex * 4;
	_InitialAddress = GetNtCurrentAddress(NtIndex);
	_HookedAddress = HookedAddress;
	//close page protection to write the SSDT
	ClosePageProtection();
		__asm{
			push ecx
				push edx
				mov ecx,KeServiceDescriptorTable
				mov ecx,[ecx]
			add ecx,_index
				mov edx,_HookedAddress
				mov [ecx],edx
				pop edx
				pop ecx
	}
	//don't be a dick to your OS. now reopen the page protection.
	OpenPageProtection();

	Write_SSDT_Hook_Table(&Global_Hook_Entry[0],NtIndex,_InitialAddress,_HookedAddress);
	//Print "hi bro, hook finished!"
	DbgPrint("Hooked:Initial Address:%X. Hooked Address:%X. NtIndex:%X.",_InitialAddress,_HookedAddress,NtIndex);
	return STATUS_SUCCESS;
}

#pragma PAGECODE
//When the driver unloads, unhook the ssdt
NTSTATUS Nt_SSDT_UnHook(ULONG index,ULONG InitialAddress)
{
	ULONG _index = index * 4;
	ClosePageProtection();
	__asm {
		push ecx
			push edx
			mov ecx,KeServiceDescriptorTable
			mov ecx,[ecx]
		add ecx,_index
			mov edx,InitialAddress
			mov [ecx],edx
			pop edx
			pop ecx
	}
	OpenPageProtection();
	return STATUS_SUCCESS;
}

#pragma PAGECODE
//used for closing page protection
void ClosePageProtection()
{
	__asm
	{
		cli
			mov eax,cr0
			and eax,not 10000h
			mov cr0,eax
	}
}

#pragma PAGECODE
void OpenPageProtection()
{
	__asm 
	{ 
		mov eax, cr0 
			or eax, 10000h 
			mov cr0, eax 
			sti 
	}   
}

#pragma PAGECODE
//Write Hook Table
void Write_SSDT_Hook_Table(HookEntry* Hook_Entry,ULONG NtIndex,ULONG InitialAddress,ULONG HookedAddress)
{
	//index in the SSDT
	Hook_Entry[SSDT_HOOK_NUMBER].NtIndex = NtIndex;
	//Initial Address
	Hook_Entry[SSDT_HOOK_NUMBER].InitialAddress = InitialAddress;
	//store hooked address
	Hook_Entry[SSDT_HOOK_NUMBER].HookedAddress = HookedAddress;
	SSDT_HOOK_NUMBER++;
}

#pragma PAGECODE

//used for determining whether PID is in the table
BOOL IsProcessProtected(DWORD PID)
{
	int i = 0;
	for(i=0;i<Protect_PID_Number;i++)
	{
		if(Global_Protect_PID_Table[i]==PID)
			return TRUE;
	}
	return FALSE;
}

#pragma PAGECODE
NTSTATUS DispatchRoutine_Write(IN PDEVICE_OBJECT pDevobj,IN PIRP pIrp)
{
	return STATUS_SUCCESS;
} 

NTSTATUS DispatchRoutine_Close(IN PDEVICE_OBJECT pDevobj,IN PIRP pIrp)
{
	return STATUS_SUCCESS;
}

#pragma PAGECODE
NTSTATUS DispatchRoutine_Create(IN PDEVICE_OBJECT pDevobj,IN PIRP pIrp)
{
	return STATUS_SUCCESS;
}

#pragma PAGECODE
NTSTATUS DispatchRoutine_Read(IN PDEVICE_OBJECT pDevobj,IN PIRP pIrp)
{
	return STATUS_SUCCESS;
}

#pragma PAGECODE
NTSTATUS DispatchRoutine_Device_Control(IN PDEVICE_OBJECT pDevobj,IN PIRP pIrp)
{
	NTSTATUS status=STATUS_UNSUCCESSFUL;
	ULONG ControlCode,info;
	//get ctrlcode
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(pIrp);
	ControlCode = stack->Parameters.DeviceIoControl.IoControlCode;
	//What is the ctrlcode?
	switch(ControlCode)
	{
		//if NtGetPhysicalAddressCode, return physical address(failed)
	case NtGetPhysicalAddressCode:
		{
			PVOID In_Physical_Address_Buffer = (PVOID)pIrp->AssociatedIrp.SystemBuffer;
			PPHYSICAL_ADDRESS Out_Physical_Address_Buffer = (PPHYSICAL_ADDRESS)pIrp->AssociatedIrp.SystemBuffer;
			DbgPrint("NtGetPhysicalAddressCode Received.\n");
			DbgPrint("The Virtual Address Received is %X\n",In_Physical_Address_Buffer);
			*(Out_Physical_Address_Buffer) = MmGetPhysicalAddress(In_Physical_Address_Buffer);
			DbgPrint("The Physical Address is %X.\n",(*(Out_Physical_Address_Buffer)));
			info = sizeof(PHYSICAL_ADDRESS);
			status = STATUS_SUCCESS;
			break;
		}
		//Very Important£º 
	case NtProcessProtectCode:
		{
			PDWORD uPID = (PDWORD)pIrp->AssociatedIrp.SystemBuffer;
			DbgPrint("NtProcessProtectCode Received.\n");
			//write the HookTable
			Global_Protect_PID_Table[Protect_PID_Number] = *uPID;
			DbgPrint("Protected Process PID Number:%d\n",*uPID);
			//protected process number + 1
			Protect_PID_Number++;
			info = 4;
			status = STATUS_SUCCESS;
			break;
		}
		//ignore other types
	default:
		{
			DbgPrint("Unknown Type NtControlCode Received.\n");
			status = STATUS_SUCCESS;
			info = 0;
			break;
		}
	}
	//bytes returned to the user
	pIrp->IoStatus.Information=info;
	//set status
	pIrp->IoStatus.Status=STATUS_SUCCESS;
	//complete request
	IoCompleteRequest(pIrp,IO_NO_INCREMENT);
	DbgPrint("DeviceIoControl Completed.\n");
	return status;
}

//create device 
#pragma INITCODE
NTSTATUS CreateDevice(IN PDRIVER_OBJECT pDriverObject)
{
	PDEVICE_OBJECT pDevObj;
	UNICODE_STRING pDevName;
	UNICODE_STRING pDevSymLinkName;
	NTSTATUS status;
	RtlInitUnicodeString(&pDevName,L"\\Device\\Hyper_Assembler");
	status = IoCreateDevice( pDriverObject,0,&pDevName,FILE_DEVICE_UNKNOWN,0, TRUE,&pDevObj);
	if(!NT_SUCCESS(status))
	{
		DbgPrint("Error creating device\n");
		return status;
	}
	DbgPrint("Device Create Succeeded\n");
	pDevObj->Flags |= DO_BUFFERED_IO;
	RtlInitUnicodeString(&pDevSymLinkName,L"\\??\\Hyper_ASM");
	status = IoCreateSymbolicLink( &pDevSymLinkName,&pDevName);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("Error Linking Name\n");
		IoDeleteDevice(pDevObj);
		return status;
	}
	DbgPrint("Linking Name Succeeded\n");
	return STATUS_SUCCESS;
} 

#pragma PAGECODE
//Hooked NtTerminateProcess
NTSTATUS HookedNtTerminateProcess(
	IN HANDLE               ProcessHandle OPTIONAL,
	IN NTSTATUS             ExitStatus)
{
	DWORD PID;
	NTSTATUS status;
	PEPROCESS eProcess;
	//Get process object
	status = ObReferenceObjectByHandle(ProcessHandle,FILE_READ_DATA,NULL,KernelMode,&eProcess,NULL); 
	if(!NT_SUCCESS(status))
	{
		return status;
	}
	//Get PID
	PID = (DWORD)PsGetProcessId(eProcess); 
	if(IsProcessProtected(PID))
	{
		//if pid = protected
		DbgPrint("Protected Process Termination Detected. Access has been denied. PID:%d\n",PID);
		//return Access Denied!
		return STATUS_ACCESS_DENIED;
	}
	DbgPrint("Normal Process Termination Detected. Call NtTerminateProcess to terminate. PID:%d\n",PID);
	//or invoke the original NtOpenProcess to handle the request
	status = InitialNtTerminateProcessAddress(ProcessHandle,ExitStatus);
	return status;
}

//The hooked NtOpenProcess
NTSTATUS HookedNtOpenProcess(
	__out PHANDLE ProcessHandle,
	__in ACCESS_MASK DesiredAccess,
	__in POBJECT_ATTRIBUTES ObjectAttributes,
	__in_opt PCLIENT_ID ClientId
	)
{
	DWORD PID;
	NTSTATUS status;
	PEPROCESS eProcess;
	status = ObReferenceObjectByHandle(ProcessHandle,FILE_READ_DATA,NULL,KernelMode,&eProcess,NULL);
	if(!NT_SUCCESS(status))
	{
		return status;
	}

	PID = (DWORD)PsGetProcessId(eProcess);
	if(IsProcessProtected(PID))
	{
		DbgPrint("Protected Process Open Detected. Access has been denied. PID:%d\n",PID);
		ProcessHandle = NULL;
		return STATUS_ACCESS_DENIED;
	}
	DbgPrint("Normal Process Open Detected. Call NtOpenProcess to proceed.\n");
	status = InitialNtOpenProcessAddress(ProcessHandle,DesiredAccess,ObjectAttributes,ClientId);
	return status;
}

void Driver_Unload(PDRIVER_OBJECT pDrv)
{
	PDEVICE_OBJECT pDevObj;
	UNICODE_STRING SymLink;
	//Create Symbol Link Name
	RtlInitUnicodeString(&SymLink,L"\\??\\Hyper_ASM");
	pDevObj = pDrv->DeviceObject;
	//DeleteDevice
	IoDeleteDevice(pDevObj);
	IoDeleteSymbolicLink(&SymLink);
	SSDT_UNHOOK_ALL();
	DbgPrint("Driver Successfully Unloaded\n");
}

//used for restoring system ssdt
void SSDT_UNHOOK_ALL()
{
	int i;
	for (i=SSDT_HOOK_NUMBER-1;i>=0;i--)
	{
		Nt_SSDT_UnHook(Global_Hook_Entry[i].NtIndex,Global_Hook_Entry[i].InitialAddress);
		DbgPrint("UnHooked:Initial Address:%X. Hooked Address:%X. NtIndex:%X.",Global_Hook_Entry[i].InitialAddress,Global_Hook_Entry[i].HookedAddress,Global_Hook_Entry[i].NtIndex);
	}
}    
#endif