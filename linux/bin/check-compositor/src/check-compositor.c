#include <X11/Xlib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int has_compositor(Display *display, int screen) {
    char prop_name[20];
    snprintf(prop_name, 20, "_NET_WM_CM_S%d", screen);
    Atom prop_atom = XInternAtom(display, prop_name, False);
    return XGetSelectionOwner(display, prop_atom) != None;
}

int main(void) {
    Display *d;
    int s;

    d = XOpenDisplay(NULL);
    if (d == NULL) {
        fprintf(stderr, "Cannot open display\n");
        exit(1);
    }

    s = DefaultScreen(d);
    printf("Has compositor? %d\n", has_compositor(d, s));

    XCloseDisplay(d);
    return 0;
}
