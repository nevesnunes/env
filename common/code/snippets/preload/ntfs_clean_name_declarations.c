#define _GNU_SOURCE

#include <dlfcn.h>
#include <stdio.h>

#include <ftw.h>
#include <glob.h>
#include <utime.h>

char * basename (const char *filename);
int glob (const char *pattern, int flags, int (*errfunc) (const char *filename, int error_code), glob_t *vector_ptr);
int glob64 (const char *pattern, int flags, int (*errfunc) (const char *filename, int error_code), glob64_t *vector_ptr);
FILE * fopen (const char *filename, const char *opentype);
FILE * fopen64 (const char *filename, const char *opentype);
FILE * freopen (const char *filename, const char *opentype, FILE *stream);
FILE * freopen64 (const char *filename, const char *opentype, FILE *stream);
int open (const char *filename, int flags, ...);
int open64 (const char *filename, int flags, ...);
int chdir (const char *filename);
int ftw (const char *filename, __ftw_func_t func, int descriptors);
int ftw64 (const char *filename, __ftw64_func_t func, int descriptors);
int nftw (const char *filename, __nftw_func_t func, int descriptors, int flag);
int nftw64 (const char *filename, __nftw64_func_t func, int descriptors, int flag);
ssize_t readlink (const char *filename, char *buffer, size_t size);
int unlink (const char *filename);
int rmdir (const char *filename);
int remove (const char *filename);
int mkdir (const char *filename, mode_t mode);
int stat (const char *filename, struct stat *buf);
int stat64 (const char *filename, struct stat64 *buf);
int lstat (const char *filename, struct stat *buf);
int lstat64 (const char *filename, struct stat64 *buf);
int chown (const char *filename, uid_t owner, gid_t group);
int chmod (const char *filename, mode_t mode);
int access (const char *filename, int how);
int utime (const char *filename, const struct utimbuf *times);
int utimes (const char *filename, const struct timeval tvp[2]);
int lutimes (const char *filename, const struct timeval tvp[2]);
int truncate (const char *filename, off_t length);
int mknod (const char *filename, mode_t mode, dev_t dev);
int mkfifo (const char *filename, mode_t mode);
int execv (const char *filename, char *const argv[]);
int execl (const char *filename, const char *arg0, ...);
int execve (const char *filename, char *const argv[], char *const env[]);
int execle (const char *filename, const char *arg0, ...);
int execvp (const char *filename, char *const argv[]);
int execlp (const char *filename, const char *arg0, ...);
long int pathconf (const char *filename, int parameter);
