#pragma once

#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <windows.h>
#include <shlwapi.h>
#include <accctrl.h>
#include <aclapi.h>
#include <shlobj_core.h>
#include <tlhelp32.h>

#pragma comment(lib, "shlwapi.lib")

#include "util.h"

typedef struct _SECTOR {
	LPCSTR Name;
	DWORD  NameOffset;
	DWORD  SerialOffset;
} SECTOR, *PSECTOR;

static SECTOR SECTORS[] = {
	{ "FAT",   0x36, 0x27 },
	{ "FAT32", 0x52, 0x43 },
	{ "NTFS",  0x03, 0x48 },
};