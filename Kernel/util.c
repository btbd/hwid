#include "stdafx.h"

PCHAR LowerStr(PCHAR str) {
	for (PCHAR s = str; *s; ++s) {
		*s = (CHAR)tolower(*s);
	}
	return str;
}

DWORD Random(PDWORD seed) {
	DWORD s = *seed * 1103515245 + 12345;
	*seed = s;
	return (s / 65536) % 32768;
}

DWORD Hash(PBYTE buffer, DWORD length) {
	if (!length) {
		return 0;
	}

	DWORD h = (*buffer ^ 0x4B9ACE2F) * 0x1000193;
	for (DWORD i = 1; i < length; ++i) {
		h = (buffer[i] ^ h) * 0x1000193;
	}
	return h;
}

PVOID SafeCopy(PVOID src, DWORD size) {
	PCHAR buffer = (PCHAR)ExAllocatePool(NonPagedPool, size);
	if (buffer) {
		MM_COPY_ADDRESS addr = { 0 };
		addr.VirtualAddress = src;

		SIZE_T read = 0;
		if (NT_SUCCESS(MmCopyMemory(buffer, addr, size, MM_COPY_MEMORY_VIRTUAL, &read)) && read == size) {
			return buffer;
		}

		ExFreePool(buffer);
	} else {
		printf("! failed to allocate pool of size %d !\n", size);
	}

	return 0;
}

VOID SpoofBuffer(DWORD seed, PBYTE buffer, DWORD length) {
	seed ^= Hash(buffer, length);
	for (DWORD i = 0; i < length; ++i) {
		buffer[i] ^= (BYTE)Random(&seed);
	}
}

PWCHAR TrimGUID(PWCHAR guid, DWORD max) {
	DWORD i = 0;
	PWCHAR start = guid;

	--max;
	for (; i < max && *start != L'{'; ++i, ++start);
	for (; i < max && guid[i++] != L'}';);
	
	guid[i] = 0;
	return start;
}

VOID ChangeIoc(PIO_STACK_LOCATION ioc, PIRP irp, PIO_COMPLETION_ROUTINE routine) {
	PIOC_REQUEST request = (PIOC_REQUEST)ExAllocatePool(NonPagedPool, sizeof(IOC_REQUEST));
	if (!request) {
		printf("! failed to allocate IOC_REQUEST !\n");
		return;
	}

	request->Buffer = irp->AssociatedIrp.SystemBuffer;
	request->BufferLength = ioc->Parameters.DeviceIoControl.OutputBufferLength;
	request->OldContext = ioc->Context;
	request->OldRoutine = ioc->CompletionRoutine;

	ioc->Control = SL_INVOKE_ON_SUCCESS;
	ioc->Context = request;
	ioc->CompletionRoutine = routine;
}

VOID SwapEndianess(PCHAR dest, PCHAR src) {
	for (size_t i = 0, l = strlen(src); i < l; i += 2) {
		dest[i] = src[i + 1];
		dest[i + 1] = src[i];
	}
}

BOOL CheckMask(PCHAR base, PCHAR pattern, PCHAR mask) {
	for (; *mask; ++base, ++pattern, ++mask) {
		if ('x' == *mask && *base != *pattern) {
			return FALSE;
		}
	}

	return TRUE;
}

PVOID FindPattern(PCHAR base, DWORD length, PCHAR pattern, PCHAR mask) {
	length -= (DWORD)strlen(mask);
	for (DWORD i = 0; i <= length; ++i) {
		PVOID addr = &base[i];
		if (CheckMask(addr, pattern, mask)) {
			return addr;
		}
	}

	return 0;
}

PVOID FindPatternImage(PCHAR base, PCHAR pattern, PCHAR mask) {
	PVOID match = 0;

	PIMAGE_NT_HEADERS headers = (PIMAGE_NT_HEADERS)(base + ((PIMAGE_DOS_HEADER)base)->e_lfanew);
	PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(headers);
	for (DWORD i = 0; i < headers->FileHeader.NumberOfSections; ++i) {
		PIMAGE_SECTION_HEADER section = &sections[i];
		if ('EGAP' == *(PINT)section->Name || memcmp(section->Name, ".text", 5) == 0) {
			match = FindPattern(base + section->VirtualAddress, section->Misc.VirtualSize, pattern, mask);
			if (match) {
				break;
			}
		}
	}

	return match;
}

PVOID GetBaseAddress(PCHAR name, PULONG out_size) {
	PVOID addr = 0;

	ULONG size = 0;
	NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, 0, 0, &size);
	if (STATUS_INFO_LENGTH_MISMATCH != status) {
		printf("! ZwQuerySystemInformation for size failed: %p !\n", status);
		return addr;
	}

	PSYSTEM_MODULE_INFORMATION modules = ExAllocatePool(NonPagedPool, size);
	if (!modules) {
		printf("! failed to allocate %d bytes for modules !\n", size);
		return addr;
	}

	if (!NT_SUCCESS(status = ZwQuerySystemInformation(SystemModuleInformation, modules, size, 0))) {
		ExFreePool(modules);
		
		printf("! ZwQuerySystemInformation failed: %p !\n", status);
		return addr;
	}

	for (ULONG i = 0; i < modules->NumberOfModules; ++i) {
		SYSTEM_MODULE m = modules->Modules[i];

		if (strstr(LowerStr((PCHAR)m.FullPathName), name)) {
			addr = m.ImageBase;
			if (out_size) {
				*out_size = m.ImageSize;
			}
			break;
		}
	}

	ExFreePool(modules);
	return addr;
}
