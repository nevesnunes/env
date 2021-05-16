// References:
// - [Game Hacking Presentation \- BSides Munich 2020 \- YouTube](https://www.youtube.com/watch?v=ncQ_qBpnWDY)

// loader
HANDLE procHandle = OpenProcess(
	PROCESS_ALL_ACCESS,
	FALSE,
	PID);
LPVOID loadFunctionAddress = (LPVOID)GetProcAddress(
	GetModuleHandle("kernel32.dll"),
	"LoadLibraryA");
LPVOID allocatedMem = LPVOID(VirtualAllocEx(
	procHandle,
	nullptr,
	MAX_PATH,
	MEM RESERVE | MEM_COMMIT,
	PAGE_READWRITE));
WriteProcessMemory(
	procHandle,
	allocatedMem,
	dllToInjectPath,
	MAX_PATH,
	nullptr);
HANDLE threadHandle = CreateRemoteThread(procHandle,
	nullptr,
	NULL,
	LPTHREAD_START_ROUTINE(LoadFunctionAddress),
	NULL,
	nullptr);
