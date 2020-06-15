#include "stdafx.h"

int main() {
	srand(GetTickCount());
	LoadLibrary(L"ntdll.dll");
	NtQueryKey = (NTQK)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryKey");
	if (!AdjustCurrentPrivilege(SE_TAKE_OWNERSHIP_NAME)) {
		printf("failed to adjust privilege\n");
		return 1;
	}

	// Monitors
	OpenThen(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Enum\\DISPLAY", {
		ForEachSubkey(key, {
			OpenThen(key, name, {
				ForEachSubkey(key, {
					OpenThen(key, name, {
						ForEachSubkey(key, {
							if (_wcsicmp(name, L"device parameters") == 0) {
								SpoofBinary(key, name, L"EDID");
								break;
							}
						});
					});
				});
			});
		});
	});

	/*
	OpenThen(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Video", {
		ForEachSubkey(key, {
			HKEY parent = key;
			WCHAR spoof[MAX_PATH] = { 0 };

			OpenThen(HKEY_LOCAL_MACHINE, L"HARDWARE\\DEVICEMAP\\VIDEO", {
				DWORD count = 0;
				DWORD size = sizeof(count);
				if (GetKeyValue(key, L"MaxObjectNumber", (LPBYTE)&count, &size)) {
					WCHAR video[MAX_PATH] = { 0 };
					WCHAR path[MAX_PATH] = { 0 };

					for (DWORD i = 0; i < count; ++i) {
						size = sizeof(path);
						wsprintf(video, L"\\Device\\Video%d", i);
						if (GetKeyValue(key, video, (LPBYTE)path, &size)) {
							LPWSTR replace = StrStrIW(path, name);
							if (replace) {
								if (!spoof[0]) {
									wcscpy(spoof, name);
									OutSpoofUnique(spoof);
									RenameSubkey(parent, name, spoof);
								}

								memcpy(replace, spoof, wcslen(spoof) * 2);
								RegSetValueEx(key, video, 0, REG_SZ, (PBYTE)path, size);
							}
						}
					}
				}
			});
		});
	});
	*/

	// SMBIOS
	DeleteValue(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\mssmbios\\Data", L"SMBiosData");

	// Motherboard
	SpoofUniqueThen(HKEY_LOCAL_MACHINE, L"SYSTEM\\HardwareConfig", L"LastConfig", {
		ForEachSubkey(key, {
			if (_wcsicmp(name, L"current")) {
				RenameSubkey(key, name, spoof);
				break;
			}
		});
	});

	// NVIDIA
	SpoofUnique(HKEY_LOCAL_MACHINE, L"SOFTWARE\\NVIDIA Corporation\\Global", L"ClientUUID");
	SpoofUnique(HKEY_LOCAL_MACHINE, L"SOFTWARE\\NVIDIA Corporation\\Global", L"PersistenceIdentifier");
	SpoofUnique(HKEY_LOCAL_MACHINE, L"SOFTWARE\\NVIDIA Corporation\\Global\\CoProcManager", L"ChipsetMatchID");

	// Misc
	DeleteKey(HKEY_LOCAL_MACHINE, L"SYSTEM\\MountedDevices");
	DeleteKey(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Dfrg\\Statistics");
	DeleteKey(HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\BitBucket\\Volume");
	DeleteKey(HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2\\CPC\\Volume");
	DeleteKey(HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2");
	DeleteValue(HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\BitBucket", L"LastEnum");

	SpoofBinary(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\TPM\\WMI", L"WindowsAIKHash");
	SpoofBinary(HKEY_CURRENT_USER, L"Software\\Microsoft\\Direct3D", L"WHQLClass");
	SpoofBinary(HKEY_CURRENT_USER, L"Software\\Classes\\Installer\\Dependencies", L"MSICache");

	OpenThen(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\MultifunctionAdapter\\0\\DiskController\\0\\DiskPeripheral", {
		ForEachSubkey(key, {
			SpoofUnique(key, name, L"Identifier");
		});
	});

	OpenThen(HKEY_LOCAL_MACHINE, L"HARDWARE\\DEVICEMAP\\Scsi", {
		ForEachSubkey(key, {
			OpenThen(key, name, {
				ForEachSubkey(key, {
					OpenThen(key, name, {
						ForEachSubkey(key, {
							if (wcsstr(name, L"arget")) {
								OpenThen(key, name, {
									ForEachSubkey(key, {
										SpoofUnique(key, name, L"Identifier");
									});
								});
							}
						});
					});
				});
			});
		});
	});

	SpoofBinary(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\TPM\\ODUID", L"RandomSeed");
	SpoofUnique(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography", L"MachineGuid");
	SpoofUnique(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\IDConfigDB\\Hardware Profiles\\0001", L"HwProfileGuid");
	SpoofUnique(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate", L"AccountDomainSid");
	SpoofUnique(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate", L"PingID");
	SpoofUnique(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate", L"SusClientId");
	SpoofBinary(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate", L"SusClientIdValidation");
	SpoofBinary(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters", L"Dhcpv6DUID");
	SpoofUnique(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\SystemInformation", L"ComputerHardwareId");
	SpoofUniques(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\SystemInformation", L"ComputerHardwareIds");
	SpoofBinary(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Internet Explorer\\Migration", L"IE Installed Date");
	SpoofUnique(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\SQMClient", L"MachineId");
	SpoofQWORD(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\SQMClient", L"WinSqmFirstSessionStartTime");
	SpoofQWORD(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"InstallTime");
	SpoofQWORD(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"InstallDate");
	SpoofBinary(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"DigitalProductId");
	SpoofBinary(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"DigitalProductId4");
	SpoofUnique(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"BuildGUID");
	SpoofUnique(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"ProductId");
	SpoofUnique(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"BuildLab");
	SpoofUnique(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"BuildLabEx");
	SpoofUnique(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000", L"_DriverProviderInfo");
	SpoofUnique(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000", L"UserModeDriverGUID");

	OpenThen(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e972-e325-11ce-bfc1-08002be10318}", {
		ForEachSubkey(key, {
			if (_wcsicmp(name, L"configuration") && _wcsicmp(name, L"properties")) {
				DeleteValue(key, name, L"NetworkAddress");
				SpoofQWORD(key, name, L"NetworkInterfaceInstallTimestamp");
			}
		});
	});

	DeleteKey(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Diagnostics\\DiagTrack\\SettingsRequests");
	SpoofQWORD(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Diagnostics\\DiagTrack\\SevilleEventlogManager", L"LastEventlogWrittenTime");
	SpoofQWORD(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SoftwareProtectionPlatform\\Activation", L"ProductActivationTime");
	DeleteValue(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SoftwareProtectionPlatform", L"BackupProductKeyDefault");
	DeleteValue(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SoftwareProtectionPlatform", L"actionlist");
	DeleteValue(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SoftwareProtectionPlatform", L"ServiceSessionId");
	DeleteKey(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist");
	DeleteKey(HKEY_CURRENT_USER, L"Software\\Hex-Rays\\IDA\\History");
	DeleteKey(HKEY_CURRENT_USER, L"Software\\Hex-Rays\\IDA\\History64");

	OpenThen(HKEY_LOCAL_MACHINE, L"HARDWARE\\UEFI\\ESRT", {
		WCHAR subkeys[0xFF][MAX_PATH] = { 0 };
		DWORD subkeys_length = 0;

		ForEachSubkey(key, {
			wcscpy(subkeys[subkeys_length++], name);
		});

		for (DWORD i = 0; i < subkeys_length; ++i) {
			WCHAR spoof[MAX_PATH] = { 0 };
			wcscpy(spoof, subkeys[i]);
			OutSpoofUnique(spoof);
			RenameSubkey(key, subkeys[i], spoof);
		}
	});

	// Tracking files
	WCHAR path[MAX_PATH] = { 0 };
	WCHAR temp[MAX_PATH] = { 0 };
	WCHAR appdata[MAX_PATH] = { 0 };
	WCHAR localappdata[MAX_PATH] = { 0 };
	GetTempPath(MAX_PATH, temp);

	SHGetFolderPath(0, CSIDL_APPDATA, 0, SHGFP_TYPE_DEFAULT, appdata);
	SHGetFolderPath(0, CSIDL_LOCAL_APPDATA, 0, SHGFP_TYPE_DEFAULT, localappdata);

	wsprintf(path, L"%ws*", temp);
	ForEachFile(path, {
		wsprintf(path, L"%ws%ws", temp, file);
		ForceDeleteFile(path);
	});

	wsprintf(path, L"%ws\\D3DSCache", localappdata);
	ForceDeleteFile(path);

	wsprintf(path, L"%ws\\NVIDIA Corporation\\GfeSDK", localappdata);
	ForceDeleteFile(path);

	wsprintf(path, L"%ws\\Microsoft\\Feeds", localappdata);
	ForceDeleteFile(path);

	wsprintf(path, L"%ws\\Microsoft\\Feeds Cache", localappdata);
	ForceDeleteFile(path);

	wsprintf(path, L"%ws\\Microsoft\\Windows\\INetCache", localappdata);
	ForceDeleteFile(path);

	wsprintf(path, L"%ws\\Microsoft\\Windows\\INetCookies", localappdata);
	ForceDeleteFile(path);

	wsprintf(path, L"%ws\\Microsoft\\Windows\\WebCache", localappdata);
	ForceDeleteFile(path);

	wsprintf(path, L"%ws\\Microsoft\\XboxLive\\AuthStateCache.dat", localappdata);
	ForceDeleteFile(path);

	for (DWORD drives = GetLogicalDrives(), drive = L'C', index = 0; drives; drives >>= 1, ++index) {
		if (drives & 1) {
			printf("\n-- DRIVE: %c --\n\n", drive);

			// Volume serial change applies after restart
			wsprintf(path, L"\\\\.\\%c:", drive);
			HANDLE device = CreateFile(path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
			if (device != INVALID_HANDLE_VALUE) {
				BYTE sector[512] = { 0 };
				DWORD read = 0;
				if (ReadFile(device, sector, sizeof(sector), &read, 0) && read == sizeof(sector)) {
					for (DWORD i = 0; i < LENGTH(SECTORS); ++i) {
						PSECTOR s = &SECTORS[i];
						if (0 == memcmp(sector + s->NameOffset, s->Name, strlen(s->Name))) {
							*(PDWORD)(sector + s->SerialOffset) = (rand() << 16) + rand();
							if (INVALID_SET_FILE_POINTER != SetFilePointer(device, 0, 0, FILE_BEGIN)) {
								WriteFile(device, sector, sizeof(sector), 0, 0);
							}

							break;
						}
					}
				}

				CloseHandle(device);
			}

			wsprintf(path, L"%c:\\Windows\\System32\\restore\\MachineGuid.txt", drive);
			ForceDeleteFile(path);

			wsprintf(path, L"%c:\\Users\\Public\\Libraries\\collection.dat", drive);
			ForceDeleteFile(path);

			wsprintf(path, L"%c:\\System Volume Information\\IndexerVolumeGuid", drive);
			ForceDeleteFile(path);

			wsprintf(path, L"%c:\\System Volume Information\\WPSettings.dat", drive);
			ForceDeleteFile(path);

			wsprintf(path, L"%c:\\System Volume Information\\tracking.log", drive);
			ForceDeleteFile(path);

			wsprintf(path, L"%c:\\ProgramData\\Microsoft\\Windows\\WER", drive);
			ForceDeleteFile(path);

			wsprintf(path, L"%c:\\Users\\Public\\Shared Files", drive);
			ForceDeleteFile(path);

			wsprintf(path, L"%c:\\Windows\\INF\\setupapi.dev.log", drive);
			ForceDeleteFile(path);

			wsprintf(path, L"%c:\\Windows\\INF\\setupapi.setup.log", drive);
			ForceDeleteFile(path);

			// wsprintf(path, L"%c:\\Windows\\System32\\spp\\store", drive);
			// ForceDeleteFile(path);

			wsprintf(path, L"%c:\\Users\\Public\\Libraries", drive);
			ForceDeleteFile(path);

			wsprintf(path, L"%c:\\MSOCache", drive);
			ForceDeleteFile(path);

			wsprintf(path, L"%c:\\ProgramData\\ntuser.pol", drive);
			ForceDeleteFile(path);

			wsprintf(path, L"%c:\\Users\\Default\\NTUSER.DAT", drive);
			ForceDeleteFile(path);

			wsprintf(path, L"%c:\\Recovery\\ntuser.sys", drive);
			ForceDeleteFile(path);

			wsprintf(path, L"%c:\\desktop.ini", drive);
			ForceDeleteFile(path);

			wsprintf(path, L"%c:\\Windows\\Prefetch\\*", drive);
			ForEachFile(path, {
				wsprintf(path, L"%c:\\Windows\\Prefetch\\%ws", drive, file);
				ForceDeleteFile(path);
			});

			wsprintf(path, L"%c:\\Users\\*", drive);
			ForEachFile(path, {
				if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
					WCHAR user[MAX_PATH] = { 0 };
					wcscpy(user, file);
					wsprintf(path, L"%c:\\Users\\%ws\\*", drive, user);
					ForEachFile(path, {
						if (StrStr(file, L"ntuser")) {
							wsprintf(path, L"%c:\\Users\\%ws\\%ws", drive, user, file);
							ForceDeleteFile(path);
						}
					});
				}
			});

			wsprintf(path, L"%c:\\Users", drive);
			RecursiveDelete(path, L"desktop.ini");

			CHAR journal[MAX_PATH] = { 0 };
			sprintf(journal, "fsutil usn deletejournal /d %c:", drive);
			system(journal);

			++drive;
		}
	}

	// Extra cleanup
	system("vssadmin delete shadows /All /Quiet");

	// WMIC holds cache of SMBIOS. With the driver loaded, starting WMIC will query the nulled SMBIOS data
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot) {
		PROCESSENTRY32 entry = { 0 };
		entry.dwSize = sizeof(entry);
		if (Process32First(snapshot, &entry)) {
			do {
				// Sometimes 'net stop' by itself isn't enough
				if (0 == _wcsicmp(entry.szExeFile, L"WmiPrvSE.exe")) {
					HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, 0, entry.th32ProcessID);
					if (INVALID_HANDLE_VALUE != process) {
						printf("Killed Winmgmt\n");
						TerminateProcess(process, 0);
						CloseHandle(process);
					}

					break;
				}
			} while (Process32Next(snapshot, &entry));
		}

		CloseHandle(snapshot);
	}

	system("net stop winmgmt /Y");

	system("pause");

	return 0;
}
