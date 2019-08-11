#pragma once

#define LENGTH(a) (sizeof(a) / sizeof(a[0]))

typedef NTSTATUS(WINAPI *NTQK)(HANDLE KeyHandle, DWORD KeyInformationClass, PVOID KeyInformation, ULONG Length, PULONG ResultLength);
NTQK NtQueryKey;

LPWSTR GetKeyPath(HKEY key);
BOOL GetKeyValue(HKEY key, LPCWSTR value, LPBYTE buffer, DWORD *size);
VOID OutSpoofUnique(LPWSTR buffer);
VOID KeySpoofOutGUID(HKEY key, LPCWSTR value, LPWSTR buffer, DWORD size);
VOID KeySpoofUnique(HKEY key, LPCWSTR value);
VOID SpoofUnique(HKEY key, LPCWSTR subkey, LPCWSTR value);
VOID SpoofUniques(HKEY key, LPCWSTR subkey, LPCWSTR value);
VOID SpoofQWORD(HKEY key, LPCWSTR subkey, LPCWSTR value);
VOID SpoofDWORD(HKEY key, LPCWSTR subkey, LPCWSTR value);
VOID SpoofBinary(HKEY key, LPCWSTR subkey, LPCWSTR value);
VOID RenameSubkey(HKEY key, LPCWSTR subkey, LPCWSTR name);
VOID DeleteValue(HKEY key, LPCWSTR subkey, LPCWSTR value);
VOID DeleteKey(HKEY key, LPCWSTR subkey);
BOOL AdjustCurrentPrivilege(LPCWSTR privilege);
VOID ForceDeleteFile(LPWSTR path);
VOID RecursiveDelete(LPWSTR dir, LPWSTR match);

#define ForEachFile(dir, callback) { \
	WIN32_FIND_DATA fd = { 0 }; \
	HANDLE f = FindFirstFile(dir, &fd); \
	do { \
		if (wcscmp(fd.cFileName, L".") && wcscmp(fd.cFileName, L"..")) { \
			LPWSTR file = fd.cFileName; \
			callback; \
		} \
	} while (FindNextFile(f, &fd)); \
	FindClose(f); \
}

#define ForEachSubkey(hkey_key, callback) { \
	WCHAR name[MAX_PATH] = { 0 }; \
	for (DWORD _i = 0, _s = sizeof(name); ERROR_SUCCESS == RegEnumKeyEx(hkey_key, _i, name, &_s, 0, 0, 0, 0); ++_i, _s = sizeof(name)) { \
		callback; \
	} \
}

#define SpoofUniqueThen(hkey_key, lpcwstr_subkey, lpcwstr_value, callback) { \
	HKEY _k = 0; \
	if (ERROR_SUCCESS != RegOpenKeyEx(hkey_key, lpcwstr_subkey, 0, KEY_ALL_ACCESS, &_k)) { \
		printf("Failed to open key: %ws\\%ws\n\n", GetKeyPath(hkey_key), lpcwstr_subkey); \
	} else { \
		WCHAR spoof[MAX_PATH] = { 0 }; \
		HKEY key = _k; \
		KeySpoofOutGUID(key, lpcwstr_value, spoof, sizeof(spoof)); \
		callback; \
		RegCloseKey(key); \
	} \
}

#define OpenThen(hkey_key, lpcwstr_subkey, callback) { \
	HKEY _k = 0; \
	if (ERROR_SUCCESS != RegOpenKeyEx(hkey_key, lpcwstr_subkey, 0, KEY_ALL_ACCESS, &_k)) { \
		printf("Failed to open key: %ws\\%ws\n\n", GetKeyPath(hkey_key), lpcwstr_subkey); \
	} else { \
		HKEY key = _k; \
		callback; \
		RegCloseKey(key); \
	} \
}