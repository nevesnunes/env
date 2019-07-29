#define WNCK_I_KNOW_THIS_IS_UNSTABLE
#include <libwnck/libwnck.h>
#include <string.h>

#define MAX_BUFFER_SIZE 1024

static void on_window_opened(WnckScreen *screen, WnckWindow *window,
                             gpointer data) {
    /* Note: when this event is emitted while screen is initialized, there is no
     * active window yet. */

    char classes[MAX_BUFFER_SIZE];
    sprintf(classes, "%s",
            wnck_application_get_name(wnck_window_get_application(window)));
    sprintf(classes + strlen(classes), ".%s",
            wnck_class_group_get_name(wnck_window_get_class_group(window)));
    g_print("0x%08lx %d %s %s\n", wnck_window_get_xid(window),
            wnck_window_is_sticky(window)
                ? -1
                : wnck_workspace_get_number(wnck_window_get_workspace(window)),
            classes, wnck_window_get_name(window));
}

static void on_active_window_changed(WnckScreen *screen,
                                     WnckWindow *previously_active_window,
                                     gpointer data) {
    WnckWindow *active_window;

    active_window = wnck_screen_get_active_window(screen);

    if (active_window)
        g_print("active: %s\n", wnck_window_get_name(active_window));
    else
        g_print("no active window\n");
}

int main(int argc, char **argv) {
    GMainLoop *loop;
    WnckScreen *screen;

    gdk_init(&argc, &argv);
    screen = wnck_screen_get_default();

    // Skip signals for initial window list
    wnck_screen_force_update(screen);

    loop = g_main_loop_new(NULL, FALSE);
    g_signal_connect(screen, "window-opened", G_CALLBACK(on_window_opened),
                     NULL);
    // g_signal_connect(screen, "active-window-changed",
    //                 G_CALLBACK(on_active_window_changed), NULL);
    g_main_loop_run(loop);
    g_main_loop_unref(loop);

    return 0;
}
