#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>

DWORD GetProcessIdByName (const std::wstring& processName) {
	PROCESSENTRY32W pe32;
	pe32.dwSize = sizeof (PROCESSENTRY32W);

	HANDLE hSnapshot = CreateToolhelp32Snapshot (TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE)
		return 0;

	if (Process32FirstW (hSnapshot, &pe32)) {
		do {
			if (!_wcsicmp (pe32.szExeFile, processName.c_str ())) {
				CloseHandle (hSnapshot);
				return pe32.th32ProcessID;
			}
		} while (Process32NextW (hSnapshot, &pe32));
	}

	CloseHandle (hSnapshot);
	return 0;
}

bool InjectDLL (DWORD pid, const std::wstring& dllPath) {
	HANDLE hProcess = OpenProcess (PROCESS_ALL_ACCESS, FALSE, pid);
	if (!hProcess) {
		std::wcerr << L"[!] Cannot open target process.\n";
		return false;
	}

	size_t size = (dllPath.length () + 1) * sizeof (wchar_t);
	LPVOID allocMem = VirtualAllocEx (hProcess, NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!allocMem) {
		std::wcerr << L"[!] VirtualAllocEx failed.\n";
		CloseHandle (hProcess);
		return false;
	}

	if (!WriteProcessMemory (hProcess, allocMem, dllPath.c_str (), size, NULL)) {
		std::wcerr << L"[!] WriteProcessMemory failed.\n";
		VirtualFreeEx (hProcess, allocMem, 0, MEM_RELEASE);
		CloseHandle (hProcess);
		return false;
	}

	HMODULE hKernel32 = GetModuleHandleW (L"kernel32.dll");
	if (!hKernel32) {
		std::wcerr << L"[!] GetModuleHandle failed.\n";
		VirtualFreeEx (hProcess, allocMem, 0, MEM_RELEASE);
		CloseHandle (hProcess);
		return false;
	}

	LPVOID loadLibraryWAddr = (LPVOID)GetProcAddress (hKernel32, "LoadLibraryW");
	if (!loadLibraryWAddr) {
		std::wcerr << L"[!] GetProcAddress for LoadLibraryW failed.\n";
		VirtualFreeEx (hProcess, allocMem, 0, MEM_RELEASE);
		CloseHandle (hProcess);
		return false;
	}

	HANDLE hThread = CreateRemoteThread (hProcess, NULL, 0,
		(LPTHREAD_START_ROUTINE)loadLibraryWAddr, allocMem, 0, NULL);

	if (!hThread) {
		std::wcerr << L"[!] CreateRemoteThread failed.\n";
		VirtualFreeEx (hProcess, allocMem, 0, MEM_RELEASE);
		CloseHandle (hProcess);
		return false;
	}

	WaitForSingleObject (hThread, INFINITE);
	CloseHandle (hThread);
	CloseHandle (hProcess);

	std::wcout << L"[+] DLL injected successfully!\n";
	return true;
}

int wmain () {
	std::wstring exeName, dllPath;
	exeName = L"PointBlank.exe"; // Replace with the target process name
	//dllPath = L"C:\\Users\\DELL\\Desktop\\cpp_repos\\PB_Hack\\Debug\\PB_Hack.dll"; // Replace with the full path to your DLL
	/*std::wcout << L"Enter target process name: ";
	std::getline (std::wcin, exeName);*/

	DWORD pid = GetProcessIdByName (exeName);
	if (!pid) {
		std::wcerr << L"[!] Process not found.\n";
		system ("pause");
		return 1;
	}

	std::wcout << L"Enter full path to DLL: ";
	std::getline (std::wcin, dllPath);

	if (dllPath.empty ()) {
		std::wcerr << L"[!] DLL path cannot be empty.\n";
		system ("pause");
		return 1;
	}

	if (!InjectDLL (pid, dllPath)) {
		std::wcerr << L"[!] DLL injection failed.\n";
		system ("pause");
		return 1;
	}

	return 0;
}