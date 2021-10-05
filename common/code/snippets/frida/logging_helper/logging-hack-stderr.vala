namespace Frida {
	private static Mutex log_mutex;
	private static Timer log_timer = null;
	private static Gee.HashMap<uint, uint> log_threads = null;
	private const uint[] log_palette = { 36, 35, 33, 32, 31, 34 };
	private static uint log_palette_offset = 0;

	public void log_event (string format, ...) {
		var builder = new StringBuilder ();

		log_mutex.lock ();

		uint time_delta;
		if (log_timer == null) {
			log_timer = new Timer ();
			log_threads = new Gee.HashMap<uint, uint> ();

			time_delta = 0;
		} else {
			time_delta = (uint) (log_timer.elapsed () * 1000.0);
			log_timer.reset ();
		}
		if (time_delta > 0) {
			builder.append_printf ("\n*** +%u ms\n", time_delta);
		}

		var tid = (uint) Gum.Process.get_current_thread_id ();

		var color = log_threads[tid];
		if (color == 0) {
			color = log_palette[log_palette_offset];
			log_palette_offset = (log_palette_offset + 1) % log_palette.length;
			log_threads[tid] = color;
		}
		builder.append_printf ("\033[0;%um", color);

		builder.append_printf ("[thread %04x] ", tid);

		var args = va_list ();
		builder.append_vprintf (format, args);

		builder.append ("\033[0m\n");

		stderr.write (builder.str.data);

		log_mutex.unlock ();
	}
}