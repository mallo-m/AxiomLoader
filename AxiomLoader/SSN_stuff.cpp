#include <stdio.h>
#include "AxiomLoader.h"

#define SSN_RANGE 0x1e
#define NTDLL_JUMPS_COUNT 5

PAXIOM_TABLE AxiomTable;

//=============================================================================
//|       So basically every syscall will have its metadata stored in a       |
//|    linked-list element. Easier to manage during parsing than a growing    |
//|                                  array.                                   |
//=============================================================================

// Init linked list
BOOL InitAxiomTable(PAXIOM_TABLE_ENTRY newEntry)
{
	PAXIOM_TABLE current;

	AxiomTable = (PAXIOM_TABLE)malloc(sizeof(AXIOM_TABLE));
	if (AxiomTable == NULL) {
		printf("HellsTable init failure\n");
		return (false);
	}
	AxiomTable->item = newEntry;
	AxiomTable->next = NULL;

	return (true);
}

// Add element to linked list
BOOL AddToAxiomTable(PAXIOM_TABLE_ENTRY newEntry)
{
	PAXIOM_TABLE current;

	current = AxiomTable;
	if (current == NULL) {
		InitAxiomTable(newEntry);
		return (true);
	}
	while (current != NULL && current->next != NULL)
		current = current->next;
	current->next = (PAXIOM_TABLE)malloc(sizeof(AXIOM_TABLE));
	if (current->next == NULL) {
		printf("AddsToTable malloc failure\n");
		return (false);
	}
	current->next->item = newEntry;
	current->next->next = NULL;

	return (true);
}

// Search element by hash
void* GetSyscallAddrByHash(const char* hash)
{
	PAXIOM_TABLE current;

	current = AxiomTable;
	while (current != NULL)
	{
		if (drunk_strcmp(current->item->dwHash, hash) == 0) {
			//LogString("[SNN] Retrieved SNN %d for hash %s\n", current->item->wSystemCall, hash);
			return (current->item->wSystemCallAddress);
		}
		current = current->next;
	}
	return (NULL);
}

// Get syscall number by hash
const int GetSNNByHash(const char* hash)
{
	PAXIOM_TABLE current;

	current = AxiomTable;
	while (current != NULL)
	{
		if (drunk_strcmp(current->item->dwHash, hash) == 0) {
			//LogString("[SNN] Retrieved SNN %d for hash %s\n", current->item->wSystemCall, hash);
			return (current->item->wSystemCall);
		}
		current = current->next;
	}
	return (-1);
}

const BOOL ExtractFunctionSNN(void* functionAddress, int* pSSN, void** pSyscallAddr)
{
	WORD cw;
	void** ntdllAddresses;

	cw = 0;
	ntdllAddresses = (void**)malloc(sizeof(void*) * (NTDLL_JUMPS_COUNT + 1));
	if (ntdllAddresses == NULL)
		return (false);
	for (int i = 0; i < (NTDLL_JUMPS_COUNT + 1); i++)
		ntdllAddresses[i] = NULL;

	while (true)
	{
		// check if syscall, in this case we are too far
		if (*((PBYTE)functionAddress + cw) == 0x0f && *((PBYTE)functionAddress + cw + 1) == 0x05)
			return (false);

		// check if ret, in this case we are also probaly too far
		if (*((PBYTE)functionAddress + cw) == 0xc3)
			return (false);

		// First opcodes should be :
		//    MOV R10, RCX
		//    MOV RCX, <syscall>
		if (*((PBYTE)functionAddress + cw) == 0x4c
			&& *((PBYTE)functionAddress + 1 + cw) == 0x8b
			&& *((PBYTE)functionAddress + 2 + cw) == 0xd1
			&& *((PBYTE)functionAddress + 3 + cw) == 0xb8
			&& *((PBYTE)functionAddress + 6 + cw) == 0x00
			&& *((PBYTE)functionAddress + 7 + cw) == 0x00) {
			BYTE high = *((PBYTE)functionAddress + 5 + cw);
			BYTE low = *((PBYTE)functionAddress + 4 + cw);

			*pSSN = ((high << 8) | low);
			for (DWORD z = 0, x = 1; z <= SSN_RANGE; z++, x++)
			{
				if (*((PBYTE)functionAddress + cw + z) == 0x0F
					&& *((PBYTE)functionAddress + cw + x) == 0x05)
				{
					PVOID syscallAddr = ((PBYTE)functionAddress + cw + z);
					//LogString("[HEAVENS HALL] Detected syscall procedure in NTDLL at 0x%p\n", syscallAddr);
					*pSyscallAddr = syscallAddr;
					break;
				}
			}

			return (true);
		}

		cw++;
	}

	return (false);
}