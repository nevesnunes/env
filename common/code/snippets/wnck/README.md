https://developer.gnome.org/libwnck/stable/getting-started.html

```
screen = wnck_screen_get_default ();

signals[WINDOW_OPENED] =
g_signal_new ("window_opened",
G_STRUCT_OFFSET (WnckScreenClass, window_opened),

emit_window_opened (WnckScreen *screen,
                    WnckWindow *window)
{
  g_signal_emit (G_OBJECT (screen),
                 signals[WINDOW_OPENED],
                 0, window);
}
```
