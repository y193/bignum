/*
 * Copyright (c) 2020 y193
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/**
 * @file bignum.h
 * @brief bignum header
 */
#ifndef BIGNUM_H
#define BIGNUM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define BIGNUM_STRING(x) #x
#define BIGNUM_CONCAT2(x, y) x##y
#define BIGNUM_CONCAT3(x, y, z) x##y##z
#define BIGNUM_STR(x) BIGNUM_STRING(x)
#define BIGNUM_CAT2(x, y) BIGNUM_CONCAT2(x, y)
#define BIGNUM_CAT3(x, y, z) BIGNUM_CONCAT3(x, y, z)

#ifndef BIGNUM_INT_BITS
#define BIGNUM_INT_BITS 32
#endif
#if BIGNUM_INT_BITS == 16
#define BIGNUM_LONG_BITS 32
#define BIGNUM_HEX_LENGTH 4
#elif BIGNUM_INT_BITS == 32
#define BIGNUM_LONG_BITS 64
#define BIGNUM_HEX_LENGTH 8
#else
#error BIGNUM_INT_BITS must be 16 or 32
#endif

#define BIGNUM_INT_T BIGNUM_CAT3(int, BIGNUM_INT_BITS, _t)
#define BIGNUM_UINT_T BIGNUM_CAT3(uint, BIGNUM_INT_BITS, _t)
#define BIGNUM_LONG_T BIGNUM_CAT3(int, BIGNUM_LONG_BITS, _t)
#define BIGNUM_ULONG_T BIGNUM_CAT3(uint, BIGNUM_LONG_BITS, _t)
#define BIGNUM_INT_MIN BIGNUM_CAT3(INT, BIGNUM_INT_BITS, _MIN)
#define BIGNUM_INT_MAX BIGNUM_CAT3(INT, BIGNUM_INT_BITS, _MAX)
#define BIGNUM_UINT_MAX BIGNUM_CAT3(UINT, BIGNUM_INT_BITS, _MAX)

/** A signed integer of the same size as \c bignum_uint_t. */
typedef BIGNUM_INT_T bignum_int_t;

/** Element type of magnitude of bignum. */
typedef BIGNUM_UINT_T bignum_uint_t;

/** A signed integer of the same size as \c bignum_ulong_t. */
typedef BIGNUM_LONG_T bignum_long_t;

/** An unsigned integer of the double length of \c bignum_uint_t. */
typedef BIGNUM_ULONG_T bignum_ulong_t;

/** Arbitrary precision integer object. */
typedef struct bignum bignum_t;

/** Division quotient and remainder. */
typedef struct bignum_qr {

    /** Quotient of the division. */
    bignum_t *quotient;

    /** Remainder of the division. */
    bignum_t *remainder;

} bignum_qr_t;

extern void bignum_free(bignum_t *x);
extern bignum_t *bignum_0(void);
extern bignum_t *bignum_from_int(bignum_int_t n);
extern bignum_t *bignum_from_uint(bignum_uint_t n);
extern bignum_t *bignum_from_hex(const char *s);
extern bignum_t *bignum_from(const bignum_t *x);
extern bignum_t *bignum_neg(bignum_t *v, const bignum_t *u);
extern bignum_t *bignum_abs(bignum_t *v, const bignum_t *u);
extern bignum_t *bignum_not(bignum_t *v, const bignum_t *u);
extern bignum_t *bignum_shl(bignum_t *v, const bignum_t *u, size_t n);
extern bignum_t *bignum_shr(bignum_t *v, const bignum_t *u, size_t n);
extern bignum_t *bignum_and(bignum_t *w, const bignum_t *u, const bignum_t *v);
extern bignum_t *bignum_or(bignum_t *w, const bignum_t *u, const bignum_t *v);
extern bignum_t *bignum_xor(bignum_t *w, const bignum_t *u, const bignum_t *v);
extern bignum_t *bignum_add(bignum_t *w, const bignum_t *u, const bignum_t *v);
extern bignum_t *bignum_sub(bignum_t *w, const bignum_t *u, const bignum_t *v);
extern bignum_t *bignum_mul(bignum_t *w, const bignum_t *u, const bignum_t *v);
extern bignum_qr_t bignum_div(bignum_t *q, bignum_t *r, const bignum_t *u,
                              const bignum_t *v);
extern int bignum_cmp(const bignum_t *u, const bignum_t *v);
extern bool bignum_eq(const bignum_t *u, const bignum_t *v);
extern bool bignum_is_0(const bignum_t *x);
extern char *bignum_to_dec(const bignum_t *x);
extern void bignum_print_dec(const bignum_t *x);
extern void bignum_print_hex(const bignum_t *x);

#endif /* BIGNUM_H */
