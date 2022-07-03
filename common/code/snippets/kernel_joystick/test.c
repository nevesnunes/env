// https://github.com/ElFeesho/OldCProjects/blob/master/noddy/joytest/test.c

#include <fcntl.h>
#include <linux/joystick.h>
#include <stdio.h>
#include <unistd.h>

void handle(struct js_event event);
int buttonDown(int buttonnum);

#define JBUT1 0
#define JBUT2 1
#define JBUT3 2
#define JBUT4 4
#define JBUT5 8
#define JBUT6 16
#define JBUT7 32
#define JBUT8 64
#define JBUT9 128

// Globals
unsigned int buttonsdown;
char jcaps[2];
char jname[128] = {0};
int x = 0;
int y = 0;

int main(int argc, char **argv) {
    int jhandle = open(argv[1], O_RDONLY);
    if (jhandle < 0) {
        printf("Couldn't open joystick device\n");
        return 1;
    }
    ioctl(jhandle, JSIOCGAXES, &jcaps[0]);
    ioctl(jhandle, JSIOCGBUTTONS, &jcaps[1]);
    ioctl(jhandle, JSIOCGNAME(128), &jname);
    close(jhandle);

    printf("Joystick has %i axis\nJoystick has %i buttons\n%s name\n",
           jcaps[0],
           jcaps[1],
           jname);

    jhandle = open(argv[1], O_RDONLY | O_NONBLOCK);

    for (;;) {
        struct js_event e;
        if (read(jhandle, &e, sizeof(struct js_event)) > 0) {
            handle(e);
        }
    }
    return 0;
}

void handle(struct js_event event) {
    // Buttons
    if (event.value == 1 && event.type == JS_EVENT_BUTTON) {
        printf("Button down: %d\n", event.number);
        buttonsdown |= 1 << event.number;
    }
    if (event.value == 0 && event.type == JS_EVENT_BUTTON) {
        buttonsdown ^= 1 << event.number;
    }
    if (event.type == JS_EVENT_AXIS) {
        printf("Axis Num: %d\n", event.number);
        if (event.number == 0 || event.number == 2) {
            x = event.value;
            if (x > 0)
                x = 2;
            if (x < 0)
                x = -2;
        }
        if (event.number == 1 || event.number == 3) {
            y = event.value;
            if (y > 0)
                y = 2;
            if (y < 0)
                y = -2;
        }
    }
    if (buttonDown(0)) {
    }
}

int buttonDown(int buttonnum) {
    return (buttonsdown & (1 << buttonnum)) >> buttonnum;
}
