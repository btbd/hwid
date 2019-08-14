#include "stdafx.h"

struct {
	HOOK Buffer[0xFF];
	ULONG Length;
} HOOKS = { 0 };

struct {
	SWAP Buffer[0xFF];
	ULONG Length;
} SWAPS = { 0 };

VOID SwapHook(PUNICODE_STRING name, PVOID swap, PVOID hook, PVOID *original) {
	PSWAP s = &SWAPS.Buffer[SWAPS.Length++];
	s->Name = *name;
	*original = s->Original = InterlockedExchangePointer(s->Swap = swap, hook);
	printf("swapped %wZ\n", name);
}

BYTE GetInstructionLength(BYTE table[], PBYTE instruction) {
	BYTE i = table[*instruction++];
	return i < 0x10 ? i : GetInstructionLength(INSTRUCTION_TABLES[i - 0x10], instruction);
}

BOOL IndirectHook(PDRIVER_OBJECT driver, PVOID dest, PVOID src, PVOID *original) {
	BOOL ret = FALSE;

	PVOID trampoline = FindPatternImage(driver->DriverStart, /* jmp rax */ "\xFF\xE0", "xx");
	if (!trampoline) {
		trampoline = FindPatternImage(driver->DriverStart, /* ret, pad, pad */ "\xC3\xCC\xCC", "xxx");
		if (trampoline) {
			trampoline = (PBYTE)trampoline + 1;
			DeProtect(trampoline, 2, {
				memcpy(mapped, /* jmp rax */ "\xFF\xE0", 2);
			}, {
				return ret;
			});
		} else {
			printf("! failed to find a valid trampoline !\n");
			return ret;
		}
	}

	BYTE length = 0;
	for (PBYTE inst = (PBYTE)src; length < 15; ) {
		BYTE l = GetInstructionLength(INSTRUCTION_TABLE, inst);
		if (!l) {
			printf("! bad instruction !\n");
			return ret;
		}

		inst += l;
		length += l;
	}

	BYTE jmp[] = {
		/* jmp back */ 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	};

	PVOID copy = ExAllocatePool(NonPagedPool, length + sizeof(jmp));
	if (copy) {
		memcpy(copy, src, length);
		*(PVOID *)&jmp[6] = (PBYTE)src + length;
		memcpy((PBYTE)copy + length, jmp, sizeof(jmp));

		BYTE hook[] = {
			/* mov rax, hook  */ 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			/* jmp trampoline */ 0xE9, 0x00, 0x00, 0x00, 0x00,
			/* extra nops     */ 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
		};

		*(PVOID *)&hook[2] = dest;
		*(PINT)&hook[11] = (INT)((LONG64)trampoline - ((LONG64)src + 15));

		DeProtect(src, length, {
			*original = copy;
			memcpy(mapped, hook, length);

			PHOOK h = &HOOKS.Buffer[HOOKS.Length++];
			h->Name = driver->DriverName;
			h->Length = length;
			h->Original = copy;
			h->Destination = dest;
			h->Source = src;

			ret = TRUE;
			printf("hooked %wZ\n", &driver->DriverName);
		}, {
			ExFreePool(copy);
		});
	} else {
		printf("! failed to allocate pool of size %d !\n", length);
	}

	return ret;
}

VOID UndoHooks() {
	for (DWORD i = 0; i < HOOKS.Length; ++i) {
		PHOOK h = &HOOKS.Buffer[i];
		if (h->Destination && h->Source && h->Original) {
			DeProtect(h->Source, h->Length, {
				memcpy(mapped, h->Original, h->Length);

				printf("unhooked %wZ\n", &h->Name);
			}, {});

			// If there's an issue with reverting the hook while unloading, there will be a BSOD.
			ExFreePool(h->Original);
		}
	}

	for (DWORD i = 0; i < SWAPS.Length; ++i) {
		PSWAP s = &SWAPS.Buffer[i];
		if (s->Swap && s->Original) {
			InterlockedExchangePointer(s->Swap, s->Original);
			printf("reverted %wZ swap\n", &s->Name);
		}
	}
}