// References:
// - [Game Hacking Presentation \- BSides Munich 2020 \- YouTube](https://www.youtube.com/watch?v=ncQ_qBpnWDY)

// dll to inject
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        MessageBox(0, "EYO ITS WORKING", "DLL", 0);
        break;
    }
    return TRUE;
}
