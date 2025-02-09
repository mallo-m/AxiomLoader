#pragma once
#ifndef AXIOM_LOADER_H
# define AXIOM_LOADER_H

# include "Typedefs.h"
# include <winhttp.h>
# include <stdint.h>
# include <iostream>
# include <vector>
# include <evntprov.h>

# define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)

PTEB RtlGetThreadEnvironmentBlock();
BOOL GetImageExportDirectory(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory);

// Drunk functions
// Why are they named drunk_* ? Well I coded this whole tool after being back from the bar while drunk and sleep deprived, so I guess this is why
// I shouldn't be telling all this, now should I ?
// The whole purpose is to render accessible standard glibc functions that are otherwise considered unsafe by the compiler, and that it doesn't let you use
// without weird-ass flags and defines macros that mess up my entire codebase.
// So screw you Microsoft, I'm doing my own strdup(), with blackjack and hookers
char* drunk_md5(const char* input);
const char* drunk_strdup(const char* str);
const int drunk_strcmp(const char* s1, const char* s2);
unsigned char* drunk_memcpy(unsigned char* dest, const unsigned char* src, size_t len);

// Yes it should be in Typedefs.h, but drunk_md5 deserves its own file, so..
typedef struct {
    uint64_t size;        // Size of input in bytes
    uint32_t buffer[4];   // Current accumulation of hash
    uint8_t input[64];    // Input to be used in the next step
    uint8_t digest[16];   // Result of algorithm
}MD5Context;

//=============================================================================
//|                                AXIOM_TABLE                                |
//|                       (where I put syscall metadata)                      |
//=============================================================================
typedef struct _AXIOM_TABLE_ENTRY
{
	void* pAddress;
	const char* humanFriendlyName;
	const char* dwHash;
	unsigned __int32 wSystemCall;
	void* wSystemCallAddress;
} AXIOM_TABLE_ENTRY, * PAXIOM_TABLE_ENTRY;

typedef struct _AXIOM_TABLE
{
	PAXIOM_TABLE_ENTRY item;
	struct _AXIOM_TABLE* next;
} AXIOM_TABLE, * PAXIOM_TABLE;

// SSN-related stuff
BOOL InitAxiomTable(PAXIOM_TABLE_ENTRY newEntry);
BOOL AddToAxiomTable(PAXIOM_TABLE_ENTRY newEntry);
const BOOL ExtractFunctionSNN(void* functionAddress, int* pSSN, void** pSyscallAddr);
void* GetSyscallAddrByHash(const char* hash);
const int GetSNNByHash(const char* hash);

//=============================================================================
//|                            File-download stuff                            |
//=============================================================================

# pragma comment(lib, "winhttp.lib")

# define DOWNLOAD_PLAIN_HTTP 0x00
# define DOWNLOAD_SECURE_HTTPS 0x01

std::vector<BYTE> DoHttpsDownload(LPCWSTR baseAddress, LPCWSTR filepath);

#endif
