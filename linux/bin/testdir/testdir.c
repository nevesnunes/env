#include <dirent.h>
#include <glib.h>

int main(int argc, char *argv[]) {
    char *dirname = argv[1];
    DIR *dir = opendir(dirname);
    struct dirent *dent;
    while ((dent = readdir(dir)) != NULL) {
        if (dent->d_type != DT_REG && dent->d_type != DT_LNK &&
            dent->d_type != DT_UNKNOWN) {
            continue;
        }
        // Skip dot files.
        if (dent->d_name[0] == '.') {
            continue;
        }
        gchar *fpath = g_build_filename(dirname, dent->d_name, NULL);
        gboolean b = g_file_test(fpath, G_FILE_TEST_IS_EXECUTABLE);
        g_free(fpath);
    }

    return 0;
}
