/*
 * Some utility routines for writing tests.
 * 
 * Copyright 2006, 2007 Board of Trustees, Leland Stanford Jr. University
 * Copyright (c) 2004, 2005, 2006
 *     by Internet Systems Consortium, Inc. ("ISC")
 * Copyright (c) 1991, 1994, 1995, 1996, 1997, 1998, 1999, 2000, 2001,
 *     2002, 2003 by The Internet Software Consortium and Rich Salz
 *
 * This code is derived from software contributed to the Internet Software
 * Consortium by Rich Salz.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef LIBTEST_H
#define LIBTEST_H 1

#include <config.h>
#include <portable/macros.h>

/*
 * Used for iterating through arrays.  ARRAY_SIZE returns the number of
 * elements in the array (useful for a < upper bound in a for loop) and
 * ARRAY_END returns a pointer to the element past the end (ISO C99 makes it
 * legal to refer to such a pointer as long as it's never dereferenced).
 */
#define ARRAY_SIZE(array)       (sizeof(array) / sizeof((array)[0]))
#define ARRAY_END(array)        (&(array)[ARRAY_SIZE(array)])

/* A global buffer into which errors_capture stores errors. */
extern char *errors;

BEGIN_DECLS

void ok(int n, int success);
void ok_int(int n, int wanted, int seen);
void ok_double(int n, double wanted, double seen);
void ok_string(int n, const char *wanted, const char *seen);
void skip(int n, const char *reason);

/* Report the same status on, or skip, the next count tests. */
void ok_block(int n, int count, int success);
void skip_block(int n, int count, const char *reason);

/* Print out the number of tests and set standard output to line buffered. */
void test_init(int count);

/*
 * Turn on capturing of errors with errors_capture.  Errors reported by warn
 * will be stored in the global errors variable.  Turn this off again with
 * errors_uncapture.  Caller is responsible for freeing errors when done.
 */
void errors_capture(void);
void errors_uncapture(void);

END_DECLS

#endif /* LIBTEST_H */
