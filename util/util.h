/* $Id$
 *
 * Utility functions.
 *
 * This is a variety of utility functions that are used internally by pieces
 * of remctl.  Many of them came originally from INN.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2005, 2006, 2007, 2008
 *     Board of Trustees, Leland Stanford Jr. University
 * Copyright (c) 2004, 2005, 2006, 2007
 *     by Internet Systems Consortium, Inc. ("ISC")
 * Copyright (c) 1991, 1994, 1995, 1996, 1997, 1998, 1999, 2000, 2001,
 *     2002, 2003 by The Internet Software Consortium and Rich Salz
 *
 * See LICENSE for licensing terms.
 */

#ifndef UTIL_UTIL_H
#define UTIL_UTIL_H 1

#include <config.h>
#include <portable/macros.h>

#include <stdarg.h>
#include <sys/types.h>

/* Used for unused parameters to silence gcc warnings. */
#define UNUSED __attribute__((__unused__))

BEGIN_DECLS

/*
 * Set permissions on a file.  owner and group may be NULL, names, or numeric
 * IDs as strings.  Mode should be NULL or the octal mode as a string.  If the
 * owner is a username and the group is NULL, sets the group to the primary
 * group of that user.  Dies on failure.
 */
void file_permissions(const char *file, const char *owner, const char *group,
                      const char *mode);

/* Concatenate NULL-terminated strings into a newly allocated string. */
char *concat(const char *first, ...);

/*
 * Given a base path and a file name, create a newly allocated path string.
 * The name will be appended to base with a / between them.  Exceptionally, if
 * name begins with a slash, it will be strdup'd and returned as-is.
 */
char *concatpath(const char *base, const char *name);

/*
 * The reporting functions.  The ones prefaced by "sys" add a colon, a space,
 * and the results of strerror(errno) to the output and are intended for
 * reporting failures of system calls.
 */
void debug(const char *, ...)
    __attribute__((__format__(printf, 1, 2)));
void notice(const char *, ...)
    __attribute__((__format__(printf, 1, 2)));
void sysnotice(const char *, ...)
    __attribute__((__format__(printf, 1, 2)));
void warn(const char *, ...)
    __attribute__((__format__(printf, 1, 2)));
void syswarn(const char *, ...)
    __attribute__((__format__(printf, 1, 2)));
void die(const char *, ...)
    __attribute__((__noreturn__, __format__(printf, 1, 2)));
void sysdie(const char *, ...)
    __attribute__((__noreturn__, __format__(printf, 1, 2)));

/*
 * Set the handlers for various message functions.  All of these functions
 * take a count of the number of handlers and then function pointers for each
 * of those handlers.  These functions are not thread-safe; they set global
 * variables.
 */
void message_handlers_debug(int count, ...);
void message_handlers_notice(int count, ...);
void message_handlers_warn(int count, ...);
void message_handlers_die(int count, ...);

/*
 * Some useful handlers, intended to be passed to message_handlers_*.  All
 * handlers take the length of the formatted message, the format, a variadic
 * argument list, and the errno setting if any.
 */
void message_log_stdout(int, const char *, va_list, int);
void message_log_stderr(int, const char *, va_list, int);
void message_log_syslog_debug(int, const char *, va_list, int);
void message_log_syslog_info(int, const char *, va_list, int);
void message_log_syslog_notice(int, const char *, va_list, int);
void message_log_syslog_warning(int, const char *, va_list, int);
void message_log_syslog_err(int, const char *, va_list, int);
void message_log_syslog_crit(int, const char *, va_list, int);

/* The type of a message handler. */
typedef void (*message_handler_func)(int, const char *, va_list, int);

/* If non-NULL, called before exit and its return value passed to exit. */
int (*message_fatal_cleanup)(void);

/*
 * If non-NULL, prepended (followed by ": ") to all messages printed by either
 * message_log_stdout or message_log_stderr.
 */
extern const char *message_program_name;

/*
 * The functions are actually macros so that we can pick up the file and line
 * number information for debugging error messages without the user having to
 * pass those in every time.
 */
#define xcalloc(n, size)        x_calloc((n), (size), __FILE__, __LINE__)
#define xmalloc(size)           x_malloc((size), __FILE__, __LINE__)
#define xrealloc(p, size)       x_realloc((p), (size), __FILE__, __LINE__)
#define xstrdup(p)              x_strdup((p), __FILE__, __LINE__)
#define xstrndup(p, size)       x_strndup((p), (size), __FILE__, __LINE__)
#define xvasprintf(p, f, a)     x_vasprintf((p), (f), (a), __FILE__, __LINE__)

/*
 * asprintf is a special case since it takes variable arguments.  If we have
 * support for variadic macros, we can still pass in the file and line and
 * just need to put them somewhere else in the argument list than last.
 * Otherwise, just call x_asprintf directly.  This means that the number of
 * arguments x_asprintf takes must vary depending on whether variadic macros
 * are supported.
 */
#ifdef HAVE_C99_VAMACROS
# define xasprintf(p, f, ...) \
    x_asprintf((p), __FILE__, __LINE__, (f), __VA_ARGS__)
#elif HAVE_GNU_VAMACROS
# define xasprintf(p, f, args...) \
    x_asprintf((p), __FILE__, __LINE__, (f), args)
#else
# define xasprintf x_asprintf
#endif

/*
 * Last two arguments are always file and line number.  These are internal
 * implementations that should not be called directly.
 */
void *x_calloc(size_t, size_t, const char *, int);
void *x_malloc(size_t, const char *, int);
void *x_realloc(void *, size_t, const char *, int);
char *x_strdup(const char *, const char *, int);
char *x_strndup(const char *, size_t, const char *, int);
int x_vasprintf(char **, const char *, va_list, const char *, int);

/* asprintf special case. */
#if HAVE_C99_VAMACROS || HAVE_GNU_VAMACROS
int x_asprintf(char **, const char *, int, const char *, ...);
#else
int x_asprintf(char **, const char *, ...);
#endif

/* Failure handler takes the function, the size, the file, and the line. */
typedef void (*xmalloc_handler_type)(const char *, size_t, const char *, int);

/* The default error handler. */
void xmalloc_fail(const char *, size_t, const char *, int);

/*
 * Assign to this variable to choose a handler other than the default, which
 * just calls sysdie.
 */
extern xmalloc_handler_type xmalloc_error_handler;

END_DECLS

#endif /* UTIL_UTIL_H */
