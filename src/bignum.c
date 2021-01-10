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
 * @file bignum.c
 * @brief bignum implementation
 */
#include "bignum.h"
#include <ctype.h>
#include <inttypes.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BIGNUM_UINT_RADIX ((bignum_ulong_t)BIGNUM_UINT_MAX + 1)
#define BIGNUM_SCNX_FMT                                                        \
    "%" BIGNUM_STR(BIGNUM_HEX_LENGTH) BIGNUM_CAT2(SCNx, BIGNUM_INT_BITS)

#define BIGNUM_AND(x, y) ((x) & (y))
#define BIGNUM_OR(x, y) ((x) | (y))
#define BIGNUM_XOR(x, y) ((x) ^ (y))

#define BIGNUM_SWAP(x, y)                                                      \
    do {                                                                       \
        const bignum_t *t = (x);                                               \
        (x) = (y);                                                             \
        (y) = t;                                                               \
    } while (0)

#define BIGNUM_DEFUN_AND_OR_XOR(fn, op)                                        \
    static void fn(size_t *l, bignum_uint_t *w, size_t m,                      \
                   const bignum_uint_t *u, size_t n, const bignum_uint_t *v,   \
                   bignum_uint_t un, bignum_uint_t vn) {                       \
        bignum_uint_t wn = op(un, vn), uc = un, vc = vn, wc = wn;              \
                                                                               \
        for (size_t i = 0; i < n; ++i) {                                       \
            bignum_uint_t ul = (u[i] ^ -un) + uc;                              \
            uc &= u[i] == 0;                                                   \
            bignum_uint_t vl = (v[i] ^ -vn) + vc;                              \
            vc &= v[i] == 0;                                                   \
            w[i] = (op(ul, vl) ^ -wn) + wc;                                    \
            wc &= w[i] == 0;                                                   \
        }                                                                      \
                                                                               \
        for (size_t i = n; i < m; ++i) {                                       \
            bignum_uint_t ul = (u[i] ^ -un) + uc;                              \
            uc &= u[i] == 0;                                                   \
            w[i] = (op(ul, -vn) ^ -wn) + wc;                                   \
            wc &= w[i] == 0;                                                   \
        }                                                                      \
                                                                               \
        if (wc) {                                                              \
            w[m] = wc;                                                         \
            *l = m + wc;                                                       \
                                                                               \
        } else                                                                 \
            *l = bn_len_words(m, w);                                           \
    }

/** Arbitrary precision integer object. */
struct bignum {

    /** Number of elements allocated to \c digits member. */
    size_t alloced;

    /** Number of valid elements in the \c digits member. */
    size_t ndigits;

    /**
     * Magnitude of bignum: \c digits[0] is the least significant int of the
     * magnitude.
     */
    bignum_uint_t *digits;

    /** Sign of bignum: \c true if negative, \c false if zero or positive. */
    bool neg;
};

static size_t bn_len_words(size_t n, const bignum_uint_t *x) {
    while (n > 1 && x[n - 1] == 0)
        --n;

    return n;
}

static size_t bn_nlz(bignum_uint_t x) {
    size_t n = BIGNUM_INT_BITS;
    size_t c = BIGNUM_INT_BITS / 2;

    do {
        bignum_uint_t y = x >> c;

        if (y != 0) {
            n -= c;
            x = y;
        }

    } while (c /= 2);

    return n - x;
}

static size_t bn_ntz_words(size_t n, const bignum_uint_t *x) {
    for (size_t i = 0; i < n; ++i)
        if (x[i] != 0)
            return i;

    return n;
}

static void bn_free_nonnull(bignum_t *x) {
    free(x->digits);
    free(x);
}

static bignum_t *bn_malloc(size_t n) {
    bignum_t *x = malloc(sizeof(bignum_t));

    if (x == NULL)
        return NULL;

    x->digits = malloc(sizeof(bignum_uint_t) * n);

    if (x->digits == NULL) {
        free(x);
        return NULL;
    }

    x->alloced = n;

    return x;
}

static bignum_t *bn_realloc(bignum_t *x, size_t n) {
    if (x->alloced >= n)
        return x;

    bignum_uint_t *d = realloc(x->digits, sizeof(bignum_uint_t) * n);

    if (d == NULL)
        return NULL;

    x->alloced = n;
    x->digits = d;

    return x;
}

static bignum_t *bn_alloc(bignum_t *x, size_t n) {
    return x == NULL ? bn_malloc(n) : bn_realloc(x, n);
}

static bignum_t *bn_0(bignum_t *x) {
    if (x == NULL) {
        x = bn_malloc(1);

        if (x == NULL)
            return NULL;
    }

    x->ndigits = 1;
    *x->digits = 0;
    x->neg = false;

    return x;
}

static bignum_t *bn_cpy(bignum_t *v, const bignum_t *u) {
    if (v == u)
        return v;

    v = bn_alloc(v, u->ndigits);

    if (v == NULL)
        return NULL;

    v->alloced = u->ndigits;
    v->ndigits = u->ndigits;
    memcpy(v->digits, u->digits, sizeof(bignum_uint_t) * u->ndigits);
    v->neg = u->neg;

    return v;
}

static bignum_t *bn_from_hex(const char *s, const char *e, size_t q, size_t r,
                             bool n) {
    bignum_t *x = bn_malloc(q + (r != 0));

    if (x == NULL)
        return NULL;

    size_t i = 0;

    // Read the string from right to left by BIGNUM_HEX_LENGTH characters.
    for (const char *p = e - BIGNUM_HEX_LENGTH; p >= s; p -= BIGNUM_HEX_LENGTH)
        if (sscanf(p, BIGNUM_SCNX_FMT, &x->digits[i++]) != 1) {
            bn_free_nonnull(x);
            return NULL;
        }

    // Read the fraction of the string as the most significant digit value.
    if (r != 0) {
        if (sscanf(s, BIGNUM_SCNX_FMT, &x->digits[i]) != 1) {
            bn_free_nonnull(x);
            return NULL;
        }

        // Shift to the right because duplicate substrings have been read.
        if (q != 0)
            x->digits[i] >>= BIGNUM_INT_BITS - r;
    }

    x->ndigits = q + (r != 0);
    x->neg = n;

    return x;
}

static void bn_shl_words(size_t *n, bignum_uint_t *v, size_t m,
                         const bignum_uint_t *u, size_t w) {
    size_t i = m - 1;

    do
        v[i + w] = u[i];
    while (i--);

    size_t j = w - 1;

    do
        v[j] = 0;
    while (j--);

    *n = m + w;
}

static void bn_shl_bits(size_t *n, bignum_uint_t *v, size_t m,
                        const bignum_uint_t *u, size_t w, size_t b) {
    v[m + w] = u[m - 1] >> (BIGNUM_INT_BITS - b);

    for (size_t i = m - 1; i > 0; --i)
        v[i + w] = u[i] << b | u[i - 1] >> (BIGNUM_INT_BITS - b);

    v[w] = u[0] << b;

    for (size_t i = w; i > 0; --i)
        v[i - 1] = 0;

    *n = m + w + (v[m + w] != 0);
}

static void bn_shr_words(size_t *n, bignum_uint_t *v, size_t m,
                         const bignum_uint_t *u, size_t w) {
    size_t i = w;

    do
        v[i - w] = u[i];
    while (++i < m);

    *n = m - w;
}

static void bn_shr_bits(size_t *n, bignum_uint_t *v, size_t m,
                        const bignum_uint_t *u, size_t w, size_t b) {
    for (size_t i = w; i < m - 1; ++i)
        v[i - w] = u[i] >> b | u[i + 1] << (BIGNUM_INT_BITS - b);

    v[m - w - 1] = u[m - 1] >> b;
    *n = m - w - (m - w - 1 > 0 && v[m - w - 1] == 0);
}

static void bn_and_digits_pos(size_t *l, bignum_uint_t *w,
                              const bignum_uint_t *u, size_t n,
                              const bignum_uint_t *v) {
    for (size_t i = 0; i < n; ++i)
        w[i] = u[i] & v[i];

    *l = bn_len_words(n, w);
}

BIGNUM_DEFUN_AND_OR_XOR(bn_and_digits, BIGNUM_AND)

static void bn_or_digits_pos(size_t *l, bignum_uint_t *w, size_t m,
                             const bignum_uint_t *u, size_t n,
                             const bignum_uint_t *v) {
    for (size_t i = 0; i < n; ++i)
        w[i] = u[i] | v[i];

    for (size_t i = n; i < m; ++i)
        w[i] = u[i];

    *l = m;
}

BIGNUM_DEFUN_AND_OR_XOR(bn_or_digits, BIGNUM_OR)

static void bn_xor_digits_pos(size_t *l, bignum_uint_t *w, size_t m,
                              const bignum_uint_t *u, size_t n,
                              const bignum_uint_t *v) {
    for (size_t i = 0; i < n; ++i)
        w[i] = u[i] ^ v[i];

    for (size_t i = n; i < m; ++i)
        w[i] = u[i];

    *l = bn_len_words(m, w);
}

BIGNUM_DEFUN_AND_OR_XOR(bn_xor_digits, BIGNUM_XOR)

static void bn_inc(size_t *n, bignum_uint_t *v, size_t m) {
    for (size_t i = 0; i < m; ++i)
        if (++v[i] != 0)
            return;

    v[m] = 1;
    *n = m + 1;
}

static void bn_add_digits(size_t *l, bignum_uint_t *w, size_t m,
                          const bignum_uint_t *u, size_t n,
                          const bignum_uint_t *v) {
    bignum_uint_t k = 0;

    for (size_t j = 0; j < n; ++j) {
        bignum_uint_t t = v[j] + k;
        k = t < k;
        t = u[j] + t;
        k |= t < u[j];
        w[j] = t;
    }

    for (size_t j = n; j < m; ++j) {
        bignum_uint_t t = u[j] + k;
        k = t < k;
        w[j] = t;
    }

    w[m] = k;
    *l = m + k;
}

static void bn_sub_digits(size_t *l, bignum_uint_t *w, size_t m,
                          const bignum_uint_t *u, size_t n,
                          const bignum_uint_t *v) {
    bignum_uint_t k = 0;

    for (size_t j = 0; j < n; ++j) {
        bignum_uint_t t = v[j] + k;
        k = t < k;
        t = u[j] - t;
        k |= t > u[j];
        w[j] = t;
    }

    for (size_t j = n; j < m; ++j) {
        bignum_uint_t t = u[j] - k;
        k = t > u[j];
        w[j] = t;
    }

    *l = bn_len_words(m, w);
}

static void bn_mul_digits(size_t *l, bignum_uint_t *w, size_t m,
                          const bignum_uint_t *u, size_t n,
                          const bignum_uint_t *v) {
    bignum_ulong_t k = 0;

    for (size_t i = 0; i < m; ++i) {
        bignum_ulong_t t = (bignum_ulong_t)u[i] * v[0] + k;
        w[i] = t;
        k = t >> BIGNUM_INT_BITS;
    }

    w[m] = k;

    for (size_t j = 1; j < n; ++j) {
        k = 0;

        for (size_t i = 0; i < m; ++i) {
            bignum_ulong_t t = (bignum_ulong_t)u[i] * v[j] + w[i + j] + k;
            w[i + j] = t;
            k = t >> BIGNUM_INT_BITS;
        }

        w[j + m] = k;
    }

    *l = m + n - (k == 0);
}

static bignum_uint_t bn_div_uint(size_t *k, bignum_uint_t *q, size_t m,
                                 const bignum_uint_t *u, bignum_uint_t v) {
    bignum_ulong_t r = 0;
    size_t i = m - 1;

    do {
        bignum_ulong_t d = r * BIGNUM_UINT_RADIX + u[i];
        q[i] = d / v;
        r = d % v;
    } while (i--);

    *k = m - (m > 1 && q[m - 1] == 0);

    return r;
}

static void bn__normalize_shl(bignum_uint_t *v, size_t m,
                              const bignum_uint_t *u, size_t b) {
    v[m] = (bignum_ulong_t)u[m - 1] >> (BIGNUM_INT_BITS - b);

    for (size_t i = m - 1; i > 0; i--)
        v[i] = u[i] << b | (bignum_ulong_t)u[i - 1] >> (BIGNUM_INT_BITS - b);

    v[0] = u[0] << b;
}

static bignum_ulong_t bn__qhat_3by2(const bignum_uint_t *u,
                                    const bignum_uint_t *v) {
    bignum_ulong_t q = (u[2] * BIGNUM_UINT_RADIX + u[1]) / v[1];
    bignum_ulong_t r = (u[2] * BIGNUM_UINT_RADIX + u[1]) % v[1];

    while (q >= BIGNUM_UINT_RADIX || q * v[0] > BIGNUM_UINT_RADIX * r + u[0]) {
        --q;
        r += v[1];

        if (r >= BIGNUM_UINT_RADIX)
            break;
    }

    return q;
}

static void bn__mulsub(bignum_uint_t *u, size_t n, const bignum_uint_t *v,
                       bignum_ulong_t q) {
    bignum_ulong_t c = 0;

    for (size_t i = 0; i < n; ++i) {
        bignum_ulong_t p = v[i] * q + c;
        u[i] -= p;
        c = (p >> BIGNUM_INT_BITS) + (u[i] > (bignum_uint_t)~p);
    }

    u[n] -= c;
}

static void bn__addback(bignum_uint_t *u, size_t n, const bignum_uint_t *v) {
    bignum_ulong_t c = 0;

    for (size_t i = 0; i < n; ++i) {
        bignum_ulong_t s = (bignum_ulong_t)u[i] + v[i] + c;
        u[i] = s;
        c = s >> BIGNUM_INT_BITS;
    }

    u[n] += c;
}

static void bn__denormalize_shr(bignum_uint_t *v, size_t m,
                                const bignum_uint_t *u, size_t b) {
    for (size_t i = 0; i < m - 1; ++i)
        v[i] = u[i] >> b | (bignum_ulong_t)u[i + 1] << (BIGNUM_INT_BITS - b);

    v[m - 1] = u[m - 1] >> b;
}

/*
 * Uses Algorithm D in Knuth section 4.3.1.
 * This program is based on the implementation of Hacker’s Delight.
 */
static void bn_div_digits(size_t *k, bignum_uint_t *q, size_t *l,
                          bignum_uint_t *r, size_t m, const bignum_uint_t *u,
                          size_t n, const bignum_uint_t *v, bignum_uint_t *un,
                          bignum_uint_t *vn) {
    size_t s = bn_nlz(v[n - 1]);

    bn__normalize_shl(vn, n, v, s);
    bn__normalize_shl(un, m, u, s);

    size_t i = m - n;

    do {
        bignum_ulong_t qhat = bn__qhat_3by2(&un[i + n - 2], &vn[n - 2]);
        bn__mulsub(&un[i], n, vn, qhat);

        if (un[i + n] != 0) {
            bn__addback(&un[i], n, vn);
            --qhat;
        }

        q[i] = qhat;

    } while (i--);

    bn__denormalize_shr(r, n, un, s);

    *k = bn_len_words(m - n + 1, q);
    *l = bn_len_words(n, r);
}

static int bn_cmp_digits(size_t m, const bignum_uint_t *u, size_t n,
                         const bignum_uint_t *v) {
    if (m < n)
        return -1;

    else if (m > n--)
        return 1;

    do
        if (u[n] < v[n])
            return -1;

        else if (u[n] > v[n])
            return 1;

    while (n--);

    return 0;
}

static bignum_t *bn_not(bignum_t *v, const bignum_t *u) {
    v = bn_alloc(v, u->ndigits + !u->neg);

    if (v == NULL)
        return NULL;

    if (u->neg)
        bn_sub_digits(&v->ndigits, v->digits, u->ndigits, u->digits, 1,
                      (bignum_uint_t[]){1});
    else
        bn_add_digits(&v->ndigits, v->digits, u->ndigits, u->digits, 1,
                      (bignum_uint_t[]){1});

    v->neg = !u->neg;

    return v;
}

static bignum_t *bn_shl(bignum_t *v, const bignum_t *u, size_t w, size_t b) {
    v = bn_alloc(v, u->ndigits + w + (b != 0));

    if (v == NULL)
        return NULL;

    if (b == 0)
        bn_shl_words(&v->ndigits, v->digits, u->ndigits, u->digits, w);
    else
        bn_shl_bits(&v->ndigits, v->digits, u->ndigits, u->digits, w, b);

    v->neg = u->neg;

    return v;
}

static bignum_t *bn_shr(bignum_t *v, const bignum_t *u, size_t w, size_t b) {
    v = bn_alloc(v, u->ndigits - w);

    if (v == NULL)
        return NULL;

    if (b == 0)
        bn_shr_words(&v->ndigits, v->digits, u->ndigits, u->digits, w);
    else
        bn_shr_bits(&v->ndigits, v->digits, u->ndigits, u->digits, w, b);

    if (u->neg) {
        bignum_uint_t x = (bignum_ulong_t)u->digits[w] << (BIGNUM_INT_BITS - b);

        if (x != 0 || bn_ntz_words(w, u->digits) != w)
            bn_inc(&v->ndigits, v->digits, v->ndigits);
    }

    v->neg = u->neg;

    return v;
}

static bignum_t *bn_and(bignum_t *w, const bignum_t *u, const bignum_t *v) {
    if (u->ndigits < v->ndigits)
        BIGNUM_SWAP(u, v);

    size_t m = v->neg ? u->ndigits : v->ndigits;
    w = bn_alloc(w, m + (u->neg & v->neg));

    if (w == NULL)
        return NULL;

    if (!u->neg & !v->neg)
        bn_and_digits_pos(&w->ndigits, w->digits, u->digits, v->ndigits,
                          v->digits);
    else
        bn_and_digits(&w->ndigits, w->digits, m, u->digits, v->ndigits,
                      v->digits, u->neg, v->neg);

    w->neg = u->neg & v->neg;

    return w;
}

static bignum_t *bn_or(bignum_t *w, const bignum_t *u, const bignum_t *v) {
    if (u->ndigits < v->ndigits)
        BIGNUM_SWAP(u, v);

    size_t m = v->neg ? v->ndigits : u->ndigits;
    w = bn_alloc(w, m + (u->neg | v->neg));

    if (w == NULL)
        return NULL;

    if (!u->neg & !v->neg)
        bn_or_digits_pos(&w->ndigits, w->digits, u->ndigits, u->digits,
                         v->ndigits, v->digits);
    else
        bn_or_digits(&w->ndigits, w->digits, m, u->digits, v->ndigits,
                     v->digits, u->neg, v->neg);

    w->neg = u->neg | v->neg;

    return w;
}

static bignum_t *bn_xor(bignum_t *w, const bignum_t *u, const bignum_t *v) {
    if (u->ndigits < v->ndigits)
        BIGNUM_SWAP(u, v);

    w = bn_alloc(w, u->ndigits + (u->neg ^ v->neg));

    if (w == NULL)
        return NULL;

    if (!u->neg & !v->neg)
        bn_xor_digits_pos(&w->ndigits, w->digits, u->ndigits, u->digits,
                          v->ndigits, v->digits);
    else
        bn_xor_digits(&w->ndigits, w->digits, u->ndigits, u->digits, v->ndigits,
                      v->digits, u->neg, v->neg);

    w->neg = u->neg ^ v->neg;

    return w;
}

static bignum_t *bn_add(bignum_t *w, const bignum_t *u, const bignum_t *v) {
    if (u->ndigits < v->ndigits)
        BIGNUM_SWAP(u, v);

    w = bn_alloc(w, u->ndigits + 1);

    if (w == NULL)
        return NULL;

    bn_add_digits(&w->ndigits, w->digits, u->ndigits, u->digits, v->ndigits,
                  v->digits);
    w->neg = u->neg;

    return w;
}

static bignum_t *bn_sub(bignum_t *w, const bignum_t *u, const bignum_t *v) {
    int c = bn_cmp_digits(u->ndigits, u->digits, v->ndigits, v->digits);

    if (c == 0)
        return bn_0(w);

    else if (c < 0)
        BIGNUM_SWAP(u, v);

    w = bn_alloc(w, u->ndigits);

    if (w == NULL)
        return NULL;

    bn_sub_digits(&w->ndigits, w->digits, u->ndigits, u->digits, v->ndigits,
                  v->digits);
    w->neg = u->neg == c > 0;

    return w;
}

static bignum_t *bn_mul(bignum_t *w, const bignum_t *u, const bignum_t *v) {
    w = bn_alloc(w, u->ndigits + v->ndigits);

    if (w == NULL)
        return NULL;

    if (u->ndigits < v->ndigits)
        BIGNUM_SWAP(u, v);

    bn_mul_digits(&w->ndigits, w->digits, u->ndigits, u->digits, v->ndigits,
                  v->digits);
    w->neg = u->neg ^ v->neg;

    return w;
}

static bignum_qr_t bn_div(const bignum_t *u, const bignum_t *v) {
    bignum_t *q = bn_malloc(u->ndigits - v->ndigits + 1);

    if (q == NULL)
        return (bignum_qr_t){NULL, NULL};

    bignum_t *r = bn_malloc(v->ndigits);

    if (r == NULL) {
        bn_free_nonnull(q);
        return (bignum_qr_t){NULL, NULL};
    }

    if (v->ndigits <= 1) {
        *r->digits = bn_div_uint(&q->ndigits, q->digits, u->ndigits, u->digits,
                                 *v->digits);
        r->ndigits = 1;

    } else {
        bignum_uint_t *un = malloc(sizeof(bignum_uint_t) * (u->ndigits + 1));

        if (un == NULL) {
            bn_free_nonnull(q);
            bn_free_nonnull(r);
            return (bignum_qr_t){NULL, NULL};
        }

        bignum_uint_t *vn = malloc(sizeof(bignum_uint_t) * (v->ndigits + 1));

        if (vn == NULL) {
            bn_free_nonnull(q);
            bn_free_nonnull(r);
            free(un);
            return (bignum_qr_t){NULL, NULL};
        }

        bn_div_digits(&q->ndigits, q->digits, &r->ndigits, r->digits,
                      u->ndigits, u->digits, v->ndigits, v->digits, un, vn);
        free(un);
        free(vn);
    }

    q->neg = (u->neg ^ v->neg) & !bignum_is_0(q);
    r->neg = u->neg & !bignum_is_0(r);

    return (bignum_qr_t){q, r};
}

/**
 * Free the memory allocated to bignum.
 *
 * @param x bignum to free memory.
 */
void bignum_free(bignum_t *x) {
    if (x != NULL)
        bn_free_nonnull(x);
}

/**
 * Returns the bignum zero.
 *
 * @return bignum zero.
 */
bignum_t *bignum_0(void) {
    return bn_0(NULL);
}

/**
 * Returns a bignum whose value is equal to the specified signed integer.
 *
 * @param n value of bignum.
 * @return a bignum representing the argument \a n.
 */
bignum_t *bignum_from_int(bignum_int_t n) {
    bignum_t *x = bignum_0();

    if (x == NULL)
        return NULL;

    *x->digits = n < 0 ? -(bignum_uint_t)n : n;
    x->neg = n < 0;

    return x;
}

/**
 * Returns a bignum whose value is equal to the specified unsigned integer.
 *
 * @param n value of bignum.
 * @return a bignum representing the argument \a n.
 */
bignum_t *bignum_from_uint(bignum_uint_t n) {
    bignum_t *x = bignum_0();

    if (x == NULL)
        return NULL;

    *x->digits = n;

    return x;
}

/**
 * Returns a bignum whose value is equal to the specified hexadecimal string.
 *
 * @param s a hexadecimal string representation.
 * @return a bignum holding the value represented by the argument \a s.
 */
bignum_t *bignum_from_hex(const char *s) {
    bool n = *s == '-';

    if (*s == '-' || *s == '+')
        ++s;

    if (*s == '\0')
        return NULL;

    while (*s == '0')
        ++s;

    if (*s == '\0')
        return bignum_0();

    const char *p = s;

    do
        if (!isxdigit((unsigned char)*p++))
            return NULL;
    while (*p != '\0');

    size_t l = p - s;
    size_t q = l / BIGNUM_HEX_LENGTH;
    size_t r = 4 * l % BIGNUM_INT_BITS;

    return bn_from_hex(s, s + l, q, r, n);
}

/**
 * Returns a bignum whose value is equal to the specified bignum.
 *
 * @param x a bignum.
 * @return a copy of the argument \a x.
 */
bignum_t *bignum_from(const bignum_t *x) {
    return bn_cpy(NULL, x);
}

/**
 * Computes the arithmetic sign inversion of bignum.
 *
 * @param v a bignum holding computation result.
 * @param u a bignum.
 * @return pointer to bignum of computation result.
 */
bignum_t *bignum_neg(bignum_t *v, const bignum_t *u) {
    v = bn_cpy(v, u);

    if (v == NULL)
        return NULL;

    v->neg = !u->neg & !bignum_is_0(u);

    return v;
}

/**
 * Computes the absolute value of bignum.
 *
 * @param v a bignum holding computation result.
 * @param u a bignum.
 * @return pointer to bignum of computation result.
 */
bignum_t *bignum_abs(bignum_t *v, const bignum_t *u) {
    return u->neg ? bignum_neg(v, u) : bn_cpy(v, u);
}

/**
 * Computes the bitwise negation of bignum.
 *
 * @param v a bignum holding computation result.
 * @param u a bignum.
 * @return pointer to bignum of computation result.
 */
bignum_t *bignum_not(bignum_t *v, const bignum_t *u) {
    return bn_not(v, u);
}

/**
 * Shifts bignum bit to the left.
 *
 * @param v a bignum holding computation result.
 * @param u a bignum.
 * @param n shift distance, in bits.
 * @return pointer to bignum of computation result.
 */
bignum_t *bignum_shl(bignum_t *v, const bignum_t *u, size_t n) {
    if (bignum_is_0(u))
        return bn_0(v);

    if (n == 0)
        return bn_cpy(v, u);

    size_t w = n / BIGNUM_INT_BITS;
    size_t b = n % BIGNUM_INT_BITS;

    return bn_shl(v, u, w, b);
}

/**
 * Shifts bignum bit to the right.
 *
 * @param v a bignum holding computation result.
 * @param u a bignum.
 * @param n shift distance, in bits.
 * @return pointer to bignum of computation result.
 */
bignum_t *bignum_shr(bignum_t *v, const bignum_t *u, size_t n) {
    if (bignum_is_0(u))
        return bn_0(v);

    if (n == 0)
        return bn_cpy(v, u);

    size_t w = n / BIGNUM_INT_BITS;
    size_t b = n % BIGNUM_INT_BITS;

    if (w >= u->ndigits)
        return bn_0(v);

    return bn_shr(v, u, w, b);
}

/**
 * Computes the bitwise AND of two bignums.
 *
 * @param w a bignum holding computation result.
 * @param u a bignum.
 * @param v value to be AND'ed with the argument \a u.
 * @return pointer to bignum of computation result.
 */
bignum_t *bignum_and(bignum_t *w, const bignum_t *u, const bignum_t *v) {
    if (bignum_is_0(u) || bignum_is_0(v))
        return bn_0(w);

    return bn_and(w, u, v);
}

/**
 * Computes the bitwise OR of two bignums.
 *
 * @param w a bignum holding computation result.
 * @param u a bignum.
 * @param v value to be OR'ed with the argument \a u.
 * @return pointer to bignum of computation result.
 */
bignum_t *bignum_or(bignum_t *w, const bignum_t *u, const bignum_t *v) {
    if (bignum_is_0(v))
        return bn_cpy(w, u);

    if (bignum_is_0(u))
        return bn_cpy(w, v);

    return bn_or(w, u, v);
}

/**
 * Computes the bitwise XOR of two bignums.
 *
 * @param w a bignum holding computation result.
 * @param u a bignum.
 * @param v value to be XOR'ed with the argument \a u.
 * @return pointer to bignum of computation result.
 */
bignum_t *bignum_xor(bignum_t *w, const bignum_t *u, const bignum_t *v) {
    if (bignum_is_0(v))
        return bn_cpy(w, u);

    if (bignum_is_0(u))
        return bn_cpy(w, v);

    return bn_xor(w, u, v);
}

/**
 * Computes the sum of two bignums.
 *
 * @param w a bignum holding computation result.
 * @param u a bignum.
 * @param v value to be added to the argument \a u.
 * @return pointer to bignum of computation result.
 */
bignum_t *bignum_add(bignum_t *w, const bignum_t *u, const bignum_t *v) {
    if (bignum_is_0(v))
        return bn_cpy(w, u);

    if (bignum_is_0(u))
        return bn_cpy(w, v);

    return u->neg == v->neg ? bn_add(w, u, v) : bn_sub(w, u, v);
}

/**
 * Computes the difference between two bignums.
 *
 * @param w a bignum holding computation result.
 * @param u a bignum.
 * @param v value to be subtracted from the argument \a u.
 * @return pointer to bignum of computation result.
 */
bignum_t *bignum_sub(bignum_t *w, const bignum_t *u, const bignum_t *v) {
    if (bignum_is_0(v))
        return bn_cpy(w, u);

    if (bignum_is_0(u))
        return bignum_neg(w, v);

    return u->neg == v->neg ? bn_sub(w, u, v) : bn_add(w, u, v);
}

/**
 * Computes the product of two bignums.
 *
 * @param w a bignum holding computation result.
 * @param u a bignum.
 * @param v value to be multiplied by the argument \a u.
 * @return pointer to bignum of computation result.
 */
bignum_t *bignum_mul(bignum_t *w, const bignum_t *u, const bignum_t *v) {
    if (bignum_is_0(u) || bignum_is_0(v))
        return bn_0(w);

    bignum_t *x = bn_mul(NULL, u, v);

    if (x == NULL)
        return NULL;

    w = bn_cpy(w, x);
    bn_free_nonnull(x);

    return w;
}

/**
 * Computes the quotient and remainder of two bignums.
 *
 * @param q a bignum holding the quotient of the computation result.
 * @param r a bignum holding the remainder of the computation result.
 * @param u a bignum.
 * @param v value by which the argument \a u is to be divided.
 * @return bignum_qr_t structure holding the computation result.
 */
bignum_qr_t bignum_div(bignum_t *q, bignum_t *r, const bignum_t *u,
                       const bignum_t *v) {
    if (q == r && q != NULL)
        return (bignum_qr_t){NULL, NULL};

    if (bignum_is_0(v))
        return (bignum_qr_t){NULL, NULL};

    if (bignum_is_0(u))
        return (bignum_qr_t){bn_0(q), bn_0(r)};

    if (u->ndigits < v->ndigits)
        return (bignum_qr_t){bn_0(q), bn_cpy(r, u)};

    bignum_qr_t qr = bn_div(u, v);

    if (qr.quotient == NULL)
        return (bignum_qr_t){NULL, NULL};

    q = bn_cpy(q, qr.quotient);
    r = bn_cpy(r, qr.remainder);
    bn_free_nonnull(qr.quotient);
    bn_free_nonnull(qr.remainder);

    return (bignum_qr_t){q, r};
}

/**
 * Compares two bignums for order.
 *
 * @param u a bignum.
 * @param v a bignum to be compared with the argument \a u for order.
 * @return -1, 0 or 1 as the first argument is less than, equal to, or greater
 *         than the second.
 */
int bignum_cmp(const bignum_t *u, const bignum_t *v) {
    if (u->neg)
        if (v->neg)
            return bn_cmp_digits(v->ndigits, v->digits, u->ndigits, u->digits);
        else
            return -1;

    else if (v->neg)
        return 1;

    else
        return bn_cmp_digits(u->ndigits, u->digits, v->ndigits, v->digits);
}

/**
 * Compares two bignums for equality.
 *
 * @param u a bignum.
 * @param v a bignum to be compared with the argument \a u for equality.
 * @return true if the arguments are equal to each other and false otherwise.
 */
bool bignum_eq(const bignum_t *u, const bignum_t *v) {
    return u == v || bignum_cmp(u, v) == 0;
}

/**
 * Compares if bignum is zero.
 *
 * @param x a bignum.
 * @return true if bignum is zero and false otherwise.
 */
bool bignum_is_0(const bignum_t *x) {
    return x->ndigits == 1 & *x->digits == 0;
}

/**
 * Returns the decimal string representation of bignum.
 *
 * @param x bignum to string.
 * @return decimal string representation of the argument \a x.
 */
char *bignum_to_dec(const bignum_t *x) {
    bignum_t *y = bignum_from(x);

    if (y == NULL)
        return NULL;

    // Allocate space for sign, decimal numbers, trailing null character
    size_t l = x->neg + x->ndigits * BIGNUM_INT_BITS / log2(10) + 2;
    size_t e = log10(BIGNUM_UINT_MAX);

    bignum_uint_t *r = malloc(sizeof(bignum_uint_t) * (l / e + 1));

    if (r == NULL) {
        bn_free_nonnull(y);
        return NULL;
    }

    // Maximum power of 10 that is less than or equal to radix
    bignum_uint_t d = pow(10, e);
    size_t i = 0;

    do
        r[i++] = bn_div_uint(&y->ndigits, y->digits, y->ndigits, y->digits, d);
    while (!bignum_is_0(y));

    bn_free_nonnull(y);

    char *s = malloc(sizeof(char) * l);

    if (s == NULL) {
        free(r);
        return NULL;
    }

    char *p = s;
    p += sprintf(p, ("-%" PRIuMAX) + !x->neg, (uintmax_t)r[--i]);

    while (i--)
        p += sprintf(p, "%0*" PRIuMAX, (int)e, (uintmax_t)r[i]);

    free(r);

    return s;
}

/**
 * Prints the decimal string representation of bignum.
 *
 * @param x bignum to print.
 */
void bignum_print_dec(const bignum_t *x) {
    char *s = bignum_to_dec(x);

    if (s == NULL)
        return;

    printf("%s\n", s);

    free(s);
}

/**
 * Prints the hexadecimal string representation of bignum.
 *
 * @param x bignum to print.
 */
void bignum_print_hex(const bignum_t *x) {
    size_t i = x->ndigits - 1;

    printf(("-%" PRIxMAX) + !x->neg, (uintmax_t)x->digits[i]);

    while (i--)
        printf("%0*" PRIxMAX, BIGNUM_HEX_LENGTH, (uintmax_t)x->digits[i]);

    printf("\n");
}
