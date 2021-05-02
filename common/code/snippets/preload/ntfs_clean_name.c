#define _GNU_SOURCE
#define NO_RTLD_HIDDEN

#include <dlfcn.h>
#include <stdio.h>

#include <fts.h>
#include <ftw.h>
#include <glob.h>
#include <limits.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <utime.h>

/**
 * Compiling:
 * ```
 * gcc ntfs_clean_name.c -Wall -fPIC -O0 -shared -ldl -o ntfs_clean_name.so
 * ```
 *
 * Pitfalls:
 * - Undocumented imported functions, e.g. __fxstatat64
 * - Consider varargs, e.g. mode when creating file:
 * ```
 * openat(AT_FDCWD, "foo", O_WRONLY|O_CREAT|O_NOCTTY|O_NONBLOCK, 0666)
 * openat(AT_FDCWD, "foo._", O_WRONLY|O_CREAT|O_NOCTTY|O_NONBLOCK, 04501)
 * ```
 */

const char *clean(const char *filename, const char *caller) {
    int len = strlen(filename);
    if (filename[len - 1] == '.') {
        printf("%s: Cleaning filename: %s\n", caller, filename);

        char *new_filename = malloc(sizeof(char) * (strlen(filename) + 2));
        strcpy(new_filename, filename);
        strncat(new_filename, "_", len + 1);
        return new_filename;
    }

    return filename;
}

char *basename(const char *filename) {
    filename = clean(filename, "basename");

    char *(*original)(const char *filename);
    original = dlsym(RTLD_NEXT, "basename");
    return (*original)(filename);
}

FILE *fopen(const char *filename, const char *opentype) {
    filename = clean(filename, "fopen");

    FILE *(*original)(const char *filename, const char *opentype);
    original = dlsym(RTLD_NEXT, "fopen");
    return (*original)(filename, opentype);
}

FILE *fopen64(const char *filename, const char *opentype) {
    filename = clean(filename, "fopen64");

    FILE *(*original)(const char *filename, const char *opentype);
    original = dlsym(RTLD_NEXT, "fopen64");
    return (*original)(filename, opentype);
}

FILE *freopen(const char *filename, const char *opentype, FILE *stream) {
    filename = clean(filename, "freopen");

    FILE *(*original)(const char *filename, const char *opentype, FILE *stream);
    original = dlsym(RTLD_NEXT, "freopen");
    return (*original)(filename, opentype, stream);
}

FILE *freopen64(const char *filename, const char *opentype, FILE *stream) {
    filename = clean(filename, "freopen64");

    FILE *(*original)(const char *filename, const char *opentype, FILE *stream);
    original = dlsym(RTLD_NEXT, "freopen64");
    return (*original)(filename, opentype, stream);
}

int open(const char *filename, int flags, ...) {
    filename = clean(filename, "open");

    int (*original)();
    original = dlsym(RTLD_NEXT, "open");

    // > The argument mode is used only when a file is created.
    // - https://www.gnu.org/software/libc/manual/html_node/Opening-and-Closing-Files.html
    struct stat stat_buf;
    if (stat(filename, &stat_buf) == 0) {
        // File exists, ignore mode.
        return (*original)(filename, flags);
    } else {
        va_list argp;
        va_start(argp, flags);
        mode_t mode = va_arg(argp, mode_t);
        va_end(argp);

        return (*original)(filename, flags, mode);
    }
}

int open64(const char *filename, int flags, ...) {
    filename = clean(filename, "open64");

    int (*original)();
    original = dlsym(RTLD_NEXT, "open64");

    // > The argument mode is used only when a file is created.
    // - https://www.gnu.org/software/libc/manual/html_node/Opening-and-Closing-Files.html
    struct stat stat_buf;
    if (stat(filename, &stat_buf) == 0) {
        // File exists, ignore mode.
        return (*original)(filename, flags);
    } else {
        va_list argp;
        va_start(argp, flags);
        mode_t mode = va_arg(argp, mode_t);
        va_end(argp);

        return (*original)(filename, flags, mode);
    }
}

int chdir(const char *filename) {
    filename = clean(filename, "chdir");

    int (*original)(const char *filename);
    original = dlsym(RTLD_NEXT, "chdir");
    return (*original)(filename);
}

int ftw(const char *filename, __ftw_func_t func, int descriptors) {
    filename = clean(filename, "ftw");

    int (*original)(const char *filename, __ftw_func_t func, int descriptors);
    original = dlsym(RTLD_NEXT, "ftw");
    return (*original)(filename, func, descriptors);
}

int ftw64(const char *filename, __ftw64_func_t func, int descriptors) {
    filename = clean(filename, "ftw64");

    int (*original)(const char *filename, __ftw64_func_t func, int descriptors);
    original = dlsym(RTLD_NEXT, "ftw64");
    return (*original)(filename, func, descriptors);
}

int nftw(const char *filename, __nftw_func_t func, int descriptors, int flag) {
    filename = clean(filename, "nftw");

    int (*original)(
        const char *filename, __nftw_func_t func, int descriptors, int flag);
    original = dlsym(RTLD_NEXT, "nftw");
    return (*original)(filename, func, descriptors, flag);
}

int nftw64(const char *filename,
           __nftw64_func_t func,
           int descriptors,
           int flag) {
    filename = clean(filename, "nftw64");

    int (*original)(
        const char *filename, __nftw64_func_t func, int descriptors, int flag);
    original = dlsym(RTLD_NEXT, "nftw64");
    return (*original)(filename, func, descriptors, flag);
}

ssize_t readlink(const char *filename, char *buffer, size_t size) {
    filename = clean(filename, "readlink");

    ssize_t (*original)(const char *filename, char *buffer, size_t size);
    original = dlsym(RTLD_NEXT, "readlink");
    return (*original)(filename, buffer, size);
}

int unlink(const char *filename) {
    filename = clean(filename, "unlink");

    int (*original)(const char *filename);
    original = dlsym(RTLD_NEXT, "unlink");
    return (*original)(filename);
}

int rmdir(const char *filename) {
    filename = clean(filename, "rmdir");

    int (*original)(const char *filename);
    original = dlsym(RTLD_NEXT, "rmdir");
    return (*original)(filename);
}

int remove(const char *filename) {
    filename = clean(filename, "remove");

    int (*original)(const char *filename);
    original = dlsym(RTLD_NEXT, "remove");
    return (*original)(filename);
}

int mkdir(const char *filename, mode_t mode) {
    filename = clean(filename, "mkdir");

    int (*original)(const char *filename, mode_t mode);
    original = dlsym(RTLD_NEXT, "mkdir");
    return (*original)(filename, mode);
}

int stat(const char *filename, struct stat *buf) {
    filename = clean(filename, "stat");

    // > The stat family functions are actually wrappers to internal functions in glibc.
    //
    // Validation:
    //
    // ```
    // # On .rela.plt, check e.g. __xstat@GLIBC_2.2.5
    // objdump /bin/stat
    // ```
    //
    // > The `stat', `fstat', `lstat' functions have to be handled special since
    // > even while not compiling the library with optimization calls to these
    // > functions in the shared library must reference the `xstat' etc functions.
    // > We have to use macros but we cannot define them in the normal headers
    // > since on user level we must use real functions.
    // - https://code.woboq.org/userspace/glibc/include/sys/stat.h.html
    // #if IS_IN (libc) || (IS_IN (rtld) && !defined NO_RTLD_HIDDEN)
    // hidden_proto (__fxstat)
    // hidden_proto (__fxstat64)
    // hidden_proto (__lxstat)
    // hidden_proto (__lxstat64)
    // hidden_proto (__xstat)
    // hidden_proto (__xstat64)
    // #endif
    int (*original)(int stat_ver, const char *filename, struct stat *buf);
    original = dlsym(RTLD_NEXT, "__xstat");
    return (*original)(_STAT_VER, filename, buf);
}

int stat64(const char *filename, struct stat64 *buf) {
    filename = clean(filename, "stat64");

    int (*original)(int stat_ver, const char *filename, struct stat64 *buf);
    original = dlsym(RTLD_NEXT, "__xstat64");
    return (*original)(_STAT_VER, filename, buf);
}

int lstat(const char *filename, struct stat *buf) {
    filename = clean(filename, "lstat");

    int (*original)(int stat_ver, const char *filename, struct stat *buf);
    original = dlsym(RTLD_NEXT, "__lxstat");
    return (*original)(_STAT_VER, filename, buf);
}

int lstat64(const char *filename, struct stat64 *buf) {
    filename = clean(filename, "lstat64");

    int (*original)(int stat_ver, const char *filename, struct stat64 *buf);
    original = dlsym(RTLD_NEXT, "__lxstat64");
    return (*original)(_STAT_VER, filename, buf);
}

int __fxstatat(int stat_ver, int dirfd, const char *pathname, struct stat *buf, int flags) {
    pathname = clean(pathname, "__fxstatat");

    int (*original)(int __ver, int __fildes, const char *__filename, struct stat *__stat_buf, int __flag);
    original = dlsym(RTLD_NEXT, "__fxstatat");
    return (*original)(_STAT_VER, dirfd, pathname, buf, flags);
}

int fstatat(int dirfd, const char *pathname, struct stat *buf, int flags) {
    pathname = clean(pathname, "fstatat");

    int (*original)(int __ver, int __fildes, const char *__filename, struct stat *__stat_buf, int __flag);
    original = dlsym(RTLD_NEXT, "__fxstatat");
    return (*original)(_STAT_VER, dirfd, pathname, buf, flags);
}

int __fxstatat64(int stat_ver, int dirfd, const char *pathname, struct stat64 *buf, int flags) {
    pathname = clean(pathname, "__fxstatat64");

    int (*original)(int __ver, int __fildes, const char *__filename, struct stat64 *__stat_buf, int __flag);
    original = dlsym(RTLD_NEXT, "__fxstatat64");
    return (*original)(_STAT_VER, dirfd, pathname, buf, flags);
}

int fstatat64(int dirfd, const char *pathname, struct stat64 *buf, int flags) {
    pathname = clean(pathname, "fstatat64");

    int (*original)(int __ver, int __fildes, const char *__filename, struct stat64 *__stat_buf, int __flag);
    original = dlsym(RTLD_NEXT, "__fxstatat64");
    return (*original)(_STAT_VER, dirfd, pathname, buf, flags);
}

FTS * fts_open (char * const *path_argv, int options, int (*compar) (const FTSENT **, const FTSENT **)) {
    const char * new_path_argv = clean(*path_argv, "fts_open");

    FTS * (*original)(char * const *path_argv, int options, int (*compar) (const FTSENT **, const FTSENT **));
    original = dlsym(RTLD_NEXT, "fts_open");
    return (*original)((char * const *)&new_path_argv, options, compar);
}

FTS * xfts_open (char * const *path_argv, int options, int (*compar) (const FTSENT **, const FTSENT **)) {
    const char * new_path_argv = clean(*path_argv, "xfts_open");

    FTS * (*original)(char * const *path_argv, int options, int (*compar) (const FTSENT **, const FTSENT **));
    original = dlsym(RTLD_NEXT, "xfts_open");
    return (*original)((char * const *)&new_path_argv, options, compar);
}

int chown(const char *filename, uid_t owner, gid_t group) {
    filename = clean(filename, "chown");

    int (*original)(const char *filename, uid_t owner, gid_t group);
    original = dlsym(RTLD_NEXT, "chown");
    return (*original)(filename, owner, group);
}

int chmod(const char *filename, mode_t mode) {
    filename = clean(filename, "chmod");

    int (*original)(const char *filename, mode_t mode);
    original = dlsym(RTLD_NEXT, "chmod");
    return (*original)(filename, mode);
}

int access(const char *filename, int how) {
    filename = clean(filename, "access");

    int (*original)(const char *filename, int how);
    original = dlsym(RTLD_NEXT, "access");
    return (*original)(filename, how);
}

int utime(const char *filename, const struct utimbuf *times) {
    filename = clean(filename, "utime");

    int (*original)(const char *filename, const struct utimbuf *times);
    original = dlsym(RTLD_NEXT, "utime");
    return (*original)(filename, times);
}

int utimes(const char *filename, const struct timeval tvp[2]) {
    filename = clean(filename, "utimes");

    int (*original)(const char *filename, const struct timeval tvp[2]);
    original = dlsym(RTLD_NEXT, "utimes");
    return (*original)(filename, tvp);
}

int lutimes(const char *filename, const struct timeval tvp[2]) {
    filename = clean(filename, "lutimes");

    int (*original)(const char *filename, const struct timeval tvp[2]);
    original = dlsym(RTLD_NEXT, "lutimes");
    return (*original)(filename, tvp);
}

int truncate(const char *filename, off_t length) {
    filename = clean(filename, "truncate");

    int (*original)(const char *filename, off_t length);
    original = dlsym(RTLD_NEXT, "truncate");
    return (*original)(filename, length);
}

int mknod(const char *filename, mode_t mode, dev_t dev) {
    filename = clean(filename, "mknod");

    int (*original)(const char *filename, mode_t mode, dev_t dev);
    original = dlsym(RTLD_NEXT, "mknod");
    return (*original)(filename, mode, dev);
}

int mkfifo(const char *filename, mode_t mode) {
    filename = clean(filename, "mkfifo");

    int (*original)(const char *filename, mode_t mode);
    original = dlsym(RTLD_NEXT, "mkfifo");
    return (*original)(filename, mode);
}

int execv(const char *filename, char *const argv[]) {
    filename = clean(filename, "execv");

    int (*original)(const char *filename, char *const argv[]);
    original = dlsym(RTLD_NEXT, "execv");
    return (*original)(filename, argv);
}

int execl(const char *filename, const char *arg0, ...) {
    filename = clean(filename, "execl");

    int (*original)();
    original = dlsym(RTLD_NEXT, "execl");

    // FIXME: Limited to 20 args.
    // > This is similar to execv, but the argv strings are specified
    // > individually instead of as an array. A null pointer must be passed
    // > as the last such argument.
    // - https://www.gnu.org/software/libc/manual/html_node/Executing-a-File.html
    va_list argp;
    va_start(argp, arg0);
    char *argX = va_arg(argp, char *);
    char **args[20];
    int i = 0;
    while (*argX != '\0' && i < 20) {
        args[i] = &argX;
        argX = va_arg(argp, char *);
        i++;
    }
    va_end(argp);

    switch (i) {
    case 1:
        return (*original)(filename, arg0, *args[0]);
    case 2:
        return (*original)(filename, arg0, *args[0], *args[1]);
    case 3:
        return (*original)(filename, arg0, *args[0], *args[1], *args[2]);
    case 4:
        return (*original)(filename, arg0, *args[0], *args[1], *args[2], *args[3]);
    case 5:
        return (*original)(filename, arg0, *args[0], *args[1], *args[2], *args[3], *args[4]);
    case 6:
        return (*original)(filename, arg0, *args[0], *args[1], *args[2], *args[3], *args[4], *args[5]);
    case 7:
        return (*original)(filename, arg0, *args[0], *args[1], *args[2], *args[3], *args[4], *args[5], *args[6]);
    case 8:
        return (*original)(filename, arg0, *args[0], *args[1], *args[2], *args[3], *args[4], *args[5], *args[6], *args[7]);
    case 9:
        return (*original)(filename, arg0, *args[0], *args[1], *args[2], *args[3], *args[4], *args[5], *args[6], *args[7], *args[8]);
    case 10:
        return (*original)(filename, arg0, *args[0], *args[1], *args[2], *args[3], *args[4], *args[5], *args[6], *args[7], *args[8], *args[9]);
    case 11:
        return (*original)(filename, arg0, *args[0], *args[1], *args[2], *args[3], *args[4], *args[5], *args[6], *args[7], *args[8], *args[9], *args[10]);
    case 12:
        return (*original)(filename, arg0, *args[0], *args[1], *args[2], *args[3], *args[4], *args[5], *args[6], *args[7], *args[8], *args[9], *args[10], *args[11]);
    case 13:
        return (*original)(filename, arg0, *args[0], *args[1], *args[2], *args[3], *args[4], *args[5], *args[6], *args[7], *args[8], *args[9], *args[10], *args[11], *args[12]);
    case 14:
        return (*original)(filename, arg0, *args[0], *args[1], *args[2], *args[3], *args[4], *args[5], *args[6], *args[7], *args[8], *args[9], *args[10], *args[11], *args[12], *args[13]);
    case 15:
        return (*original)(filename, arg0, *args[0], *args[1], *args[2], *args[3], *args[4], *args[5], *args[6], *args[7], *args[8], *args[9], *args[10], *args[11], *args[12], *args[13], *args[14]);
    case 16:
        return (*original)(filename, arg0, *args[0], *args[1], *args[2], *args[3], *args[4], *args[5], *args[6], *args[7], *args[8], *args[9], *args[10], *args[11], *args[12], *args[13], *args[14], *args[15]);
    case 17:
        return (*original)(filename, arg0, *args[0], *args[1], *args[2], *args[3], *args[4], *args[5], *args[6], *args[7], *args[8], *args[9], *args[10], *args[11], *args[12], *args[13], *args[14], *args[15], *args[16]);
    case 18:
        return (*original)(filename, arg0, *args[0], *args[1], *args[2], *args[3], *args[4], *args[5], *args[6], *args[7], *args[8], *args[9], *args[10], *args[11], *args[12], *args[13], *args[14], *args[15], *args[16], *args[17]);
    case 19:
        return (*original)(filename, arg0, *args[0], *args[1], *args[2], *args[3], *args[4], *args[5], *args[6], *args[7], *args[8], *args[9], *args[10], *args[11], *args[12], *args[13], *args[14], *args[15], *args[16], *args[17], *args[18]);
    case 20:
        return (*original)(filename, arg0, *args[0], *args[1], *args[2], *args[3], *args[4], *args[5], *args[6], *args[7], *args[8], *args[9], *args[10], *args[11], *args[12], *args[13], *args[14], *args[15], *args[16], *args[17], *args[18], *args[19]);
    default:
        return (*original)(filename, arg0);
    }
}

int execve(const char *filename, char *const argv[], char *const env[]) {
    filename = clean(filename, "execve");

    int (*original)(
        const char *filename, char *const argv[], char *const env[]);
    original = dlsym(RTLD_NEXT, "execve");
    return (*original)(filename, argv, env);
}

int execle(const char *filename, const char *arg0, ...) {
    filename = clean(filename, "execle");

    int (*original)();
    original = dlsym(RTLD_NEXT, "execle");

    // FIXME: Limited to 20 args.
    // > This is similar to execl, but permits you to specify the environment
    // > for the new program explicitly. The environment argument is passed
    // > following the null pointer that marks the last argv argument, and should
    // > be an array of strings in the same format as for the environ variable.
    // - https://www.gnu.org/software/libc/manual/html_node/Executing-a-File.html
    va_list argp;
    va_start(argp, arg0);
    char *argX = va_arg(argp, char *);
    char **args[20];
    int i = 0;
    while (*argX != '\0' && i < 20) {
        args[i] = &argX;
        argX = va_arg(argp, char *);
        i++;
    }
    char **const env = va_arg(argp, char **);
    va_end(argp);

    switch (i) {
    case 1:
        return (*original)(filename, arg0, *args[0], env);
    case 2:
        return (*original)(filename, arg0, *args[0], *args[1], env);
    case 3:
        return (*original)(filename, arg0, *args[0], *args[1], *args[2], env);
    case 4:
        return (*original)(filename, arg0, *args[0], *args[1], *args[2], *args[3], env);
    case 5:
        return (*original)(filename, arg0, *args[0], *args[1], *args[2], *args[3], *args[4], env);
    case 6:
        return (*original)(filename, arg0, *args[0], *args[1], *args[2], *args[3], *args[4], *args[5], env);
    case 7:
        return (*original)(filename, arg0, *args[0], *args[1], *args[2], *args[3], *args[4], *args[5], *args[6], env);
    case 8:
        return (*original)(filename, arg0, *args[0], *args[1], *args[2], *args[3], *args[4], *args[5], *args[6], *args[7], env);
    case 9:
        return (*original)(filename, arg0, *args[0], *args[1], *args[2], *args[3], *args[4], *args[5], *args[6], *args[7], *args[8], env);
    case 10:
        return (*original)(filename, arg0, *args[0], *args[1], *args[2], *args[3], *args[4], *args[5], *args[6], *args[7], *args[8], *args[9], env);
    case 11:
        return (*original)(filename, arg0, *args[0], *args[1], *args[2], *args[3], *args[4], *args[5], *args[6], *args[7], *args[8], *args[9], *args[10], env);
    case 12:
        return (*original)(filename, arg0, *args[0], *args[1], *args[2], *args[3], *args[4], *args[5], *args[6], *args[7], *args[8], *args[9], *args[10], *args[11], env);
    case 13:
        return (*original)(filename, arg0, *args[0], *args[1], *args[2], *args[3], *args[4], *args[5], *args[6], *args[7], *args[8], *args[9], *args[10], *args[11], *args[12], env);
    case 14:
        return (*original)(filename, arg0, *args[0], *args[1], *args[2], *args[3], *args[4], *args[5], *args[6], *args[7], *args[8], *args[9], *args[10], *args[11], *args[12], *args[13], env);
    case 15:
        return (*original)(filename, arg0, *args[0], *args[1], *args[2], *args[3], *args[4], *args[5], *args[6], *args[7], *args[8], *args[9], *args[10], *args[11], *args[12], *args[13], *args[14], env);
    case 16:
        return (*original)(filename, arg0, *args[0], *args[1], *args[2], *args[3], *args[4], *args[5], *args[6], *args[7], *args[8], *args[9], *args[10], *args[11], *args[12], *args[13], *args[14], *args[15], env);
    case 17:
        return (*original)(filename, arg0, *args[0], *args[1], *args[2], *args[3], *args[4], *args[5], *args[6], *args[7], *args[8], *args[9], *args[10], *args[11], *args[12], *args[13], *args[14], *args[15], *args[16], env);
    case 18:
        return (*original)(filename, arg0, *args[0], *args[1], *args[2], *args[3], *args[4], *args[5], *args[6], *args[7], *args[8], *args[9], *args[10], *args[11], *args[12], *args[13], *args[14], *args[15], *args[16], *args[17], env);
    case 19:
        return (*original)(filename, arg0, *args[0], *args[1], *args[2], *args[3], *args[4], *args[5], *args[6], *args[7], *args[8], *args[9], *args[10], *args[11], *args[12], *args[13], *args[14], *args[15], *args[16], *args[17], *args[18], env);
    case 20:
        return (*original)(filename, arg0, *args[0], *args[1], *args[2], *args[3], *args[4], *args[5], *args[6], *args[7], *args[8], *args[9], *args[10], *args[11], *args[12], *args[13], *args[14], *args[15], *args[16], *args[17], *args[18], *args[19], env);
    default:
        return (*original)(filename, arg0, env);
    }
}

int execvp(const char *filename, char *const argv[]) {
    filename = clean(filename, "execvp");

    int (*original)(const char *filename, char *const argv[]);
    original = dlsym(RTLD_NEXT, "execvp");
    return (*original)(filename, argv);
}

int execlp(const char *filename, const char *arg0, ...) {
    filename = clean(filename, "execlp");

    int (*original)();
    original = dlsym(RTLD_NEXT, "execlp");

    // FIXME: Limited to 20 args.
    // > This function is like execl, except that it performs the same
    // > file name searching as the execvp function.
    // - https://www.gnu.org/software/libc/manual/html_node/Executing-a-File.html
    va_list argp;
    va_start(argp, arg0);
    char *argX = va_arg(argp, char *);
    char **args[20];
    int i = 0;
    while (*argX != '\0' && i < 20) {
        args[i] = &argX;
        argX = va_arg(argp, char *);
        i++;
    }
    va_end(argp);

    switch (i) {
    case 1:
        return (*original)(filename, arg0, *args[0]);
    case 2:
        return (*original)(filename, arg0, *args[0], *args[1]);
    case 3:
        return (*original)(filename, arg0, *args[0], *args[1], *args[2]);
    case 4:
        return (*original)(filename, arg0, *args[0], *args[1], *args[2], *args[3]);
    case 5:
        return (*original)(filename, arg0, *args[0], *args[1], *args[2], *args[3], *args[4]);
    case 6:
        return (*original)(filename, arg0, *args[0], *args[1], *args[2], *args[3], *args[4], *args[5]);
    case 7:
        return (*original)(filename, arg0, *args[0], *args[1], *args[2], *args[3], *args[4], *args[5], *args[6]);
    case 8:
        return (*original)(filename, arg0, *args[0], *args[1], *args[2], *args[3], *args[4], *args[5], *args[6], *args[7]);
    case 9:
        return (*original)(filename, arg0, *args[0], *args[1], *args[2], *args[3], *args[4], *args[5], *args[6], *args[7], *args[8]);
    case 10:
        return (*original)(filename, arg0, *args[0], *args[1], *args[2], *args[3], *args[4], *args[5], *args[6], *args[7], *args[8], *args[9]);
    case 11:
        return (*original)(filename, arg0, *args[0], *args[1], *args[2], *args[3], *args[4], *args[5], *args[6], *args[7], *args[8], *args[9], *args[10]);
    case 12:
        return (*original)(filename, arg0, *args[0], *args[1], *args[2], *args[3], *args[4], *args[5], *args[6], *args[7], *args[8], *args[9], *args[10], *args[11]);
    case 13:
        return (*original)(filename, arg0, *args[0], *args[1], *args[2], *args[3], *args[4], *args[5], *args[6], *args[7], *args[8], *args[9], *args[10], *args[11], *args[12]);
    case 14:
        return (*original)(filename, arg0, *args[0], *args[1], *args[2], *args[3], *args[4], *args[5], *args[6], *args[7], *args[8], *args[9], *args[10], *args[11], *args[12], *args[13]);
    case 15:
        return (*original)(filename, arg0, *args[0], *args[1], *args[2], *args[3], *args[4], *args[5], *args[6], *args[7], *args[8], *args[9], *args[10], *args[11], *args[12], *args[13], *args[14]);
    case 16:
        return (*original)(filename, arg0, *args[0], *args[1], *args[2], *args[3], *args[4], *args[5], *args[6], *args[7], *args[8], *args[9], *args[10], *args[11], *args[12], *args[13], *args[14], *args[15]);
    case 17:
        return (*original)(filename, arg0, *args[0], *args[1], *args[2], *args[3], *args[4], *args[5], *args[6], *args[7], *args[8], *args[9], *args[10], *args[11], *args[12], *args[13], *args[14], *args[15], *args[16]);
    case 18:
        return (*original)(filename, arg0, *args[0], *args[1], *args[2], *args[3], *args[4], *args[5], *args[6], *args[7], *args[8], *args[9], *args[10], *args[11], *args[12], *args[13], *args[14], *args[15], *args[16], *args[17]);
    case 19:
        return (*original)(filename, arg0, *args[0], *args[1], *args[2], *args[3], *args[4], *args[5], *args[6], *args[7], *args[8], *args[9], *args[10], *args[11], *args[12], *args[13], *args[14], *args[15], *args[16], *args[17], *args[18]);
    case 20:
        return (*original)(filename, arg0, *args[0], *args[1], *args[2], *args[3], *args[4], *args[5], *args[6], *args[7], *args[8], *args[9], *args[10], *args[11], *args[12], *args[13], *args[14], *args[15], *args[16], *args[17], *args[18], *args[19]);
    default:
        return (*original)(filename, arg0);
    }
}

long int pathconf(const char *filename, int parameter) {
    filename = clean(filename, "pathconf");

    long int (*original)(const char *filename, int parameter);
    original = dlsym(RTLD_NEXT, "pathconf");
    return (*original)(filename, parameter);
}
