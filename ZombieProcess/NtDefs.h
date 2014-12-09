/*
	All the required types and structures, SDK doesn't define undocumented stuff
*/

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#define ProcessBasicInformation 0

typedef struct _LSA_UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
}  OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _PROCESS_BASIC_INFORMATION {
	PVOID Reserved1;
	PVOID PebBaseAddress;
	PVOID Reserved2[2];
	ULONG_PTR UniqueProcessId;
	PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;

typedef struct _PROCESS_BASIC_INFORMATION64
{
	NTSTATUS	ExitStatus;
	ULONG		Reserved0;
	ULONG64		PebBaseAddress;
	ULONG64		AffinityMask;
	LONG		BasePriority;
	ULONG		Reserved1;
	ULONG64		uUniqueProcessId;
	ULONG64		uInheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION64, *PPROCESS_BASIC_INFORMATION64;

typedef NTSTATUS (WINAPI *TypeNtUnmapViewOfSection)(
	HANDLE ProcessHandle,
	PVOID BaseAddress);

typedef NTSTATUS (WINAPI *TypeNtCreateSection)(
	PHANDLE SectionHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PLARGE_INTEGER MaximumSize,
	ULONG SectionPageProtection,
	ULONG AllocationAttributes,
	HANDLE FileHandle
	);

typedef NTSTATUS (WINAPI *TypeNtMapViewOfSection)(
	HANDLE SectionHandle, 
	HANDLE ProcessHandle,
	PVOID *BaseAddress, 
	ULONG_PTR ZeroBits, 
	SIZE_T CommitSize, 
	PLARGE_INTEGER SectionOffset, 
	PSIZE_T ViewSize, 
	DWORD InheritDisposition, 
	ULONG AllocationType, 
	ULONG Win32Protect);

typedef NTSTATUS (WINAPI *TypeNtQueryInformationProcess)(
	HANDLE ProcessHandle,
	DWORD ProcessInformationClass,
	PVOID ProcessInformation,
	ULONG ProcessInformationLength,
	PULONG ReturnLength
	);

typedef NTSTATUS (WINAPI *TypeNtClose)(
	HANDLE Handle
	);
