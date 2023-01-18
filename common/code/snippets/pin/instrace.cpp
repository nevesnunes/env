#include "pin.H"
#include <stdio.h>

// https://reverseengineering.stackexchange.com/questions/19309/i-want-to-trace-all-instructions-with-pintool-strange-behaviour

VOID dump(UINT64 insAddr, std::string insDis) {
    printf("%lx\t%s\n", insAddr, insDis.c_str());
}

VOID callback_instruction(INS ins, VOID *v) {
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)dump, IARG_ADDRINT,
        INS_Address(ins), IARG_PTR, new string(INS_Disassemble(ins)),
        IARG_END);
}

int main(int argc, char *argv[]) {
    if (PIN_Init(argc, argv)) {
        printf("Error @PIN_Init\n");
        return 1;
    }

    INS_AddInstrumentFunction(callback_instruction, 0);
    PIN_StartProgram();

    return 0;
}
