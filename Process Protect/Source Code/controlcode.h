#ifndef _controlcode_H_
#define _controlcode_H_

#define NtGetPhysicalAddressCode CTL_CODE(FILE_DEVICE_UNKNOWN,0x801,METHOD_BUFFERED,FILE_ANY_ACCESS)

#define NtProcessProtectCode CTL_CODE(FILE_DEVICE_UNKNOWN,0x802,METHOD_BUFFERED,FILE_ANY_ACCESS)

#define NtOpenProcessIndex 0x7A

#define NtTerminateProcessIndex 0x101

#define NtQuerySystemInformationIndex 0xAD

#endif