// Trace/instrument return statements in C
//
// References:
// - https://twitter.com/vegard_no/status/1516700881407905797
// - https://godbolt.org/z/cq3Y5jsbM

#include <stdio.h>

void trace_return(const char *fn) { printf("@@@ returning from %s()\n", fn); }

#define return while(trace_return(__FUNCTION__), 1) return

// Type your code here, or load an example.
int square(int num) { return num * num; }

void foo() {
    if (1)
        return;
}

int main() {
    int num = 123;
    printf("square(%d) = %d\n", num, square(num));
    foo();

    return 0;
}
