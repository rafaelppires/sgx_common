#ifndef _LIBCPROXY_H_DEFINED_
#define _LIBCPROXY_H_DEFINED_

#include <stdarg.h>
#include <stdlib.h> // for size_t

/* STDIO */
#define SEEK_SET 0
#define SEEK_CUR 1
#define SEEK_END 2

#define _IOFBF 0
#define _IOLBF 1
#define _IONBF 2

#define EOF (-1)

#ifdef __cplusplus
extern "C" {
#define _Noreturn
#endif

struct _IO_FILE;
typedef struct _IO_FILE FILE;
typedef long off_t;

struct _IO_FILE {
    unsigned flags;
    unsigned char *rpos, *rend;
    int (*close)(FILE *);
    unsigned char *wend, *wpos;
    unsigned char *mustbezero_1;
    unsigned char *wbase;
    size_t (*read)(FILE *, unsigned char *, size_t);
    size_t (*write)(FILE *, const unsigned char *, size_t);
    off_t (*seek)(FILE *, off_t, int);
    unsigned char *buf;
    size_t buf_size;
    FILE *prev, *next;
    int fd;
    int pipe_pid;
    long lockcount;
    short dummy3;
    signed char mode;
    signed char lbf;
    volatile int lock;
    volatile int waiters;
    void *cookie;
    off_t off;
    char *getln_buf;
    void *mustbezero_2;
    unsigned char *shend;
    off_t shlim, shcnt;
    FILE *prev_locked, *next_locked;
    struct __locale_struct *locale;
};

extern FILE *const stdin; 
extern FILE *const stdout;
extern FILE *const stderr;

FILE *fopen(const char *__restrict, const char *__restrict);
FILE *freopen(const char *__restrict, const char *__restrict, FILE *__restrict);
int fclose(FILE *);

int remove(const char *);
int rename(const char *, const char *);

int feof(FILE *);
int ferror(FILE *);
int fflush(FILE *);
void clearerr(FILE *);

int fseek(FILE *, long, int);
long ftell(FILE *);

int getc(FILE *);
int ungetc(int, FILE *);

int fputc(int,FILE *);
char *fgets(char *__restrict, int, FILE *__restrict);
int fprintf(FILE *__restrict, const char *__restrict, ...);
size_t fread(void *__restrict, size_t, size_t, FILE *__restrict);
size_t fwrite(const void *__restrict, size_t, size_t, FILE *__restrict);

int setvbuf(FILE *__restrict, char *__restrict, int, size_t);

#define L_tmpnam 20
char *tmpnam(char *);
FILE *tmpfile(void);

/* STDLIB */
int rand (void);
void srand (unsigned);
char *getenv (const char *);
int system (const char *);
void exit (int);

/* STRING */
char *strcpy (char *__restrict, const char *__restrict);

/* TIME */
#include <time.h>
#define CLOCKS_PER_SEC 1000000L
typedef long time_t;
typedef long clock_t;
typedef long suseconds_t;
time_t mktime (struct tm *);
struct tm *gmtime (const time_t *);
struct tm *localtime (const time_t *);
time_t time (time_t *__timer);
clock_t clock (void);
struct timeval { time_t tv_sec; suseconds_t tv_usec; };

/* LOCALE */
#define LC_CTYPE    0
#define LC_NUMERIC  1
#define LC_TIME     2
#define LC_COLLATE  3
#define LC_MONETARY 4
#define LC_MESSAGES 5
#define LC_ALL      6

struct lconv {
    char *decimal_point;
    char *thousands_sep;
    char *grouping;

    char *int_curr_symbol;
    char *currency_symbol;
    char *mon_decimal_point;
    char *mon_thousands_sep;
    char *mon_grouping;
    char *positive_sign;
    char *negative_sign;
    char int_frac_digits;
    char frac_digits;
    char p_cs_precedes;
    char p_sep_by_space;
    char n_cs_precedes;
    char n_sep_by_space;
    char p_sign_posn;
    char n_sign_posn;
    char int_p_cs_precedes;
    char int_p_sep_by_space;
    char int_n_cs_precedes;
    char int_n_sep_by_space;
    char int_p_sign_posn;
    char int_n_sign_posn;
};

char *setlocale (int, const char *);
struct lconv *localeconv(void);

/* GETOPT */
int getopt(int, char * const [], const char *);
extern char *optarg;
extern int optind, opterr, optopt, optreset;

/* SIGNAL */

#define SIGHUP    1
#define SIGINT    2
#define SIGQUIT   3
#define SIGILL    4
#define SIGTRAP   5
#define SIGABRT   6
#define SIGIOT    SIGABRT
#define SIGBUS    7
#define SIGFPE    8
#define SIGKILL   9
#define SIGUSR1   10
#define SIGSEGV   11
#define SIGUSR2   12
#define SIGPIPE   13
#define SIGALRM   14
#define SIGTERM   15
#define SIGSTKFLT 16
#define SIGCHLD   17
#define SIGCONT   18
#define SIGSTOP   19
#define SIGTSTP   20
#define SIGTTIN   21
#define SIGTTOU   22
#define SIGURG    23
#define SIGXCPU   24
#define SIGXFSZ   25
#define SIGVTALRM 26
#define SIGPROF   27
#define SIGWINCH  28
#define SIGIO     29
#define SIGPOLL   29
#define SIGPWR    30
#define SIGSYS    31
#define SIGUNUSED SIGSYS

int vfprintf (FILE *, const char *, va_list);

#ifdef __cplusplus
}

namespace std {
    typedef struct _IO_FILE FILE;
}

#include "libcpp_mock.h"
#endif

#endif

