#include "bignum.h"
#include <assert.h>
#include <stdio.h>

#define RUN(f)                                                                 \
    do {                                                                       \
        puts(#f);                                                              \
        f();                                                                   \
    } while (0)

typedef bignum_t *(*func_2op)(bignum_t *, const bignum_t *);
typedef bignum_t *(*func_3op)(bignum_t *, const bignum_t *, const bignum_t *);
typedef bignum_t *(*func_shift)(bignum_t *, const bignum_t *, size_t n);
typedef bignum_qr_t (*func_div)(bignum_t *, bignum_t *, const bignum_t *,
                                const bignum_t *);

static bool cmp_2op(func_2op f, const char *us, const char *vs) {
    bignum_t *u = bignum_from_hex(us);
    bignum_t *v = vs == NULL ? NULL : bignum_from_hex(vs);
    bignum_t *w = f(NULL, u);

    bool t = (v == NULL && w == NULL) || bignum_eq(v, w);

    if (!t) {
        printf("expected: %s\n", vs);
        printf("actual: ");
        bignum_print_hex(w);
    }

    bignum_free(u);
    bignum_free(v);
    bignum_free(w);

    return t;
}

static bool cmp_3op(func_3op f, const char *us, const char *vs,
                    const char *ws) {
    bignum_t *u = bignum_from_hex(us);
    bignum_t *v = bignum_from_hex(vs);
    bignum_t *w = ws == NULL ? NULL : bignum_from_hex(ws);
    bignum_t *x = f(NULL, u, v);

    bool t = (w == NULL && x == NULL) || bignum_eq(w, x);

    if (!t) {
        printf("expected: %s\n", ws);
        printf("actual: ");
        bignum_print_hex(x);
    }

    bignum_free(u);
    bignum_free(v);
    bignum_free(w);
    bignum_free(x);

    return t;
}

static bool cmp_shift(func_shift f, const char *us, size_t n, const char *vs) {
    bignum_t *u = bignum_from_hex(us);
    bignum_t *v = vs == NULL ? NULL : bignum_from_hex(vs);
    bignum_t *w = f(NULL, u, n);

    bool t = (v == NULL && w == NULL) || bignum_eq(v, w);

    if (!t) {
        printf("expected: %s\n", vs);
        printf("actual: ");
        bignum_print_hex(w);
    }

    bignum_free(u);
    bignum_free(v);
    bignum_free(w);

    return t;
}

static bool cmp_div(func_div f, const char *us, const char *vs, const char *qs,
                    const char *rs) {
    bignum_t *u = bignum_from_hex(us);
    bignum_t *v = bignum_from_hex(vs);
    bignum_t *q = qs == NULL ? NULL : bignum_from_hex(qs);
    bignum_t *r = rs == NULL ? NULL : bignum_from_hex(rs);
    bignum_qr_t qr = f(NULL, NULL, u, v);

    bool t = (q == NULL && qr.quotient == NULL && r == NULL &&
              qr.remainder == NULL) ||
             (bignum_eq(q, qr.quotient) && bignum_eq(r, qr.remainder));

    bignum_free(u);
    bignum_free(v);
    bignum_free(q);
    bignum_free(r);
    bignum_free(qr.quotient);
    bignum_free(qr.remainder);

    return t;
}

static void test_bignum_0(void) {
    assert(bignum_eq(bignum_0(), bignum_from_hex("0")));
}

static void test_bignum_from_int(void) {
    assert(bignum_eq(bignum_from_int(0), bignum_from_hex("0")));
    assert(bignum_eq(bignum_from_int(1), bignum_from_hex("1")));
    assert(bignum_eq(bignum_from_int(-1), bignum_from_hex("-1")));

    if (sizeof(bignum_int_t) == 4) {
        assert(bignum_eq(bignum_from_int(-0x80000000),
                         bignum_from_hex("-80000000")));
        assert(bignum_eq(bignum_from_int(0x7fffffff),
                         bignum_from_hex("7fffffff")));
    }
}

static void test_bignum_from_uint(void) {
    assert(bignum_eq(bignum_from_uint(0), bignum_from_hex("0")));
    assert(bignum_eq(bignum_from_uint(1), bignum_from_hex("1")));

    if (sizeof(bignum_int_t) == 4) {
        assert(bignum_eq(bignum_from_uint(0xffffffffUL),
                         bignum_from_hex("ffffffff")));
    }
}

static void test_bignum_from_hex(void) {
    assert(bignum_from_hex("") == NULL);
    assert(bignum_from_hex("-") == NULL);
    assert(bignum_from_hex("+") == NULL);
    assert(bignum_from_hex("g") == NULL);
    assert(bignum_from_hex("0x0") == NULL);
    assert(bignum_from_hex("123456789abcdefg") == NULL);
    assert(bignum_eq(bignum_from_hex("0"), bignum_from_hex("0")));
    assert(bignum_eq(bignum_from_hex("00"), bignum_from_hex("0")));
    assert(bignum_eq(bignum_from_hex("-0"), bignum_from_hex("0")));
    assert(bignum_eq(bignum_from_hex("+0"), bignum_from_hex("0")));
}

static void test_bignum_from(void) {
    assert(bignum_eq(bignum_from(bignum_from_hex("0")), bignum_from_hex("0")));
    assert(bignum_eq(bignum_from(bignum_from_hex("1")), bignum_from_hex("1")));
    assert(
        bignum_eq(bignum_from(bignum_from_hex("-1")), bignum_from_hex("-1")));
    assert(bignum_eq(bignum_from(bignum_from_hex("-ffffffff")),
                     bignum_from_hex("-ffffffff")));
    assert(bignum_eq(bignum_from(bignum_from_hex("100000000")),
                     bignum_from_hex("100000000")));
}

static void test_bignum_neg(void) {
    assert(cmp_2op(bignum_neg, "0", "0"));
    assert(cmp_2op(bignum_neg, "1", "-1"));
    assert(cmp_2op(bignum_neg, "-1", "1"));
    assert(cmp_2op(bignum_neg, "123456789abcdef0", "-123456789abcdef0"));
    assert(cmp_2op(bignum_neg, "-123456789abcdef0", "123456789abcdef0"));

    bignum_t *u = bignum_from_hex("123456789abcdef0");
    bignum_t *v = bignum_neg(u, u);

    assert(v == u);
    assert(bignum_eq(v, bignum_from_hex("-123456789abcdef0")));
}

static void test_bignum_abs(void) {
    assert(cmp_2op(bignum_abs, "0", "0"));
    assert(cmp_2op(bignum_abs, "1", "1"));
    assert(cmp_2op(bignum_abs, "-1", "1"));
    assert(cmp_2op(bignum_abs, "123456789abcdef0", "123456789abcdef0"));
    assert(cmp_2op(bignum_abs, "-123456789abcdef0", "123456789abcdef0"));

    bignum_t *u = bignum_from_hex("-123456789abcdef0");
    bignum_t *v = bignum_abs(u, u);

    assert(v == u);
    assert(bignum_eq(v, bignum_from_hex("123456789abcdef0")));
}

static void test_bignum_not(void) {
    assert(cmp_2op(bignum_not, "0", "-1"));
    assert(cmp_2op(bignum_not, "1", "-2"));
    assert(cmp_2op(bignum_not, "-1", "0"));
    assert(cmp_2op(bignum_not, "ffffffff", "-100000000"));
    assert(cmp_2op(bignum_not, "-100000000", "ffffffff"));
    assert(cmp_2op(bignum_not, "ffffffffffffffff", "-10000000000000000"));
    assert(cmp_2op(bignum_not, "-10000000000000000", "ffffffffffffffff"));
    assert(cmp_2op(bignum_not, "123456789abcdef0", "-123456789abcdef1"));
    assert(cmp_2op(bignum_not, "-123456789abcdef0", "123456789abcdeef"));

    bignum_t *u = bignum_from_hex("123456789abcdef0");
    bignum_t *v = bignum_not(u, u);

    assert(v == u);
    assert(bignum_eq(v, bignum_from_hex("-123456789abcdef1")));
}

static void test_bignum_shl(void) {
    assert(cmp_shift(bignum_shl, "0", 0, "0"));
    assert(cmp_shift(bignum_shl, "1", 0, "1"));
    assert(cmp_shift(bignum_shl, "0", 1, "0"));
    assert(cmp_shift(bignum_shl, "1", 1, "2"));
    assert(cmp_shift(bignum_shl, "-1", 0, "-1"));
    assert(cmp_shift(bignum_shl, "-1", 1, "-2"));
    assert(cmp_shift(bignum_shl, "-ffffffff", 1, "-1fffffffe"));
    assert(cmp_shift(bignum_shl, "-100000000", 1, "-200000000"));
    assert(cmp_shift(bignum_shl, "-ffffffffffffffff", 1, "-1fffffffffffffffe"));
    assert(
        cmp_shift(bignum_shl, "-10000000000000000", 1, "-20000000000000000"));
    assert(cmp_shift(bignum_shl, "123456789abcdef0", 31,
                     "91a2b3c4d5e6f7800000000"));
    assert(cmp_shift(bignum_shl, "123456789abcdef0", 32,
                     "123456789abcdef000000000"));
    assert(cmp_shift(bignum_shl, "123456789abcdef0", 33,
                     "2468acf13579bde000000000"));
    assert(cmp_shift(bignum_shl, "123456789abcdef0", 127,
                     "91a2b3c4d5e6f7800000000000000000000000000000000"));

    bignum_t *u = bignum_from_hex("123456789abcdef0");
    bignum_t *v = bignum_shl(u, u, 31);

    assert(v == u);
    assert(bignum_eq(v, bignum_from_hex("91a2b3c4d5e6f7800000000")));
}

static void test_bignum_shr(void) {
    assert(cmp_shift(bignum_shr, "0", 0, "0"));
    assert(cmp_shift(bignum_shr, "1", 0, "1"));
    assert(cmp_shift(bignum_shr, "0", 1, "0"));
    assert(cmp_shift(bignum_shr, "1", 1, "0"));
    assert(cmp_shift(bignum_shr, "-1", 0, "-1"));
    assert(cmp_shift(bignum_shr, "-1", 1, "-1"));
    assert(cmp_shift(bignum_shr, "-1fffffffe", 1, "-ffffffff"));
    assert(cmp_shift(bignum_shr, "-1ffffffff", 1, "-100000000"));
    assert(cmp_shift(bignum_shr, "-1fffffffffffffffe", 1, "-ffffffffffffffff"));
    assert(
        cmp_shift(bignum_shr, "-1ffffffffffffffff", 1, "-10000000000000000"));
    assert(cmp_shift(bignum_shr, "91a2b3c4d5e6f7800000000", 31,
                     "123456789abcdef0"));
    assert(cmp_shift(bignum_shr, "123456789abcdef000000000", 32,
                     "123456789abcdef0"));
    assert(cmp_shift(bignum_shr, "2468acf13579bde000000000", 33,
                     "123456789abcdef0"));
    assert(cmp_shift(bignum_shr,
                     "91a2b3c4d5e6f7800000000000000000000000000000000", 127,
                     "123456789abcdef0"));

    bignum_t *u = bignum_from_hex("91a2b3c4d5e6f7800000000");
    bignum_t *v = bignum_shr(u, u, 31);

    assert(v == u);
    assert(bignum_eq(v, bignum_from_hex("123456789abcdef0")));
}

static void test_bignum_and(void) {
    assert(cmp_3op(bignum_and, "0", "0", "0"));
    assert(cmp_3op(bignum_and, "1", "0", "0"));
    assert(cmp_3op(bignum_and, "0", "1", "0"));
    assert(cmp_3op(bignum_and, "1", "1", "1"));
    assert(cmp_3op(bignum_and, "0", "-1", "0"));
    assert(cmp_3op(bignum_and, "-1", "0", "0"));
    assert(cmp_3op(bignum_and, "-80000000", "-80000001", "-100000000"));
    assert(cmp_3op(bignum_and, "-80000000", "-FFFFFFFF80000001",
                   "-10000000000000000"));
    assert(cmp_3op(bignum_and, "-8000000000000000", "-8000000000000001",
                   "-10000000000000000"));
    assert(cmp_3op(bignum_and, "-8000000000000000", "-FFFFFFFF8000000000000001",
                   "-1000000000000000000000000"));
    assert(cmp_3op(bignum_and, "123456789abcdef0", "fedcba9876543210",
                   "1214121812141210"));
    assert(cmp_3op(bignum_and, "123456789abcdef0", "-fedcba9876543210",
                   "20446088a8ccf0"));
    assert(cmp_3op(bignum_and, "-123456789abcdef0", "fedcba9876543210",
                   "ecc8a88064402010"));
    assert(cmp_3op(bignum_and, "-123456789abcdef0", "-fedcba9876543210",
                   "-fefcfef8fefcfef0"));
    assert(cmp_3op(bignum_and, "123456789abcdef0123456789abcdef0", "77777777",
                   "12345670"));
    assert(cmp_3op(bignum_and, "123456789abcdef0123456789abcdef0", "-77777777",
                   "123456789abcdef01234567888888880"));
    assert(cmp_3op(bignum_and, "-123456789abcdef0123456789abcdef0", "77777777",
                   "65432110"));
    assert(cmp_3op(bignum_and, "-123456789abcdef0123456789abcdef0", "-77777777",
                   "-123456789abcdef01234567900000000"));

    bignum_t *u = bignum_from_hex("123456789abcdef0");
    bignum_t *w = bignum_and(u, u, u);

    assert(w == u);
    assert(bignum_eq(w, bignum_from_hex("123456789abcdef0")));
}

static void test_bignum_or(void) {
    assert(cmp_3op(bignum_or, "0", "0", "0"));
    assert(cmp_3op(bignum_or, "1", "0", "1"));
    assert(cmp_3op(bignum_or, "0", "1", "1"));
    assert(cmp_3op(bignum_or, "1", "1", "1"));
    assert(cmp_3op(bignum_or, "0", "-1", "-1"));
    assert(cmp_3op(bignum_or, "-1", "0", "-1"));
    assert(cmp_3op(bignum_or, "123456789abcdef0", "fedcba9876543210",
                   "fefcfef8fefcfef0"));
    assert(cmp_3op(bignum_or, "123456789abcdef0", "-fedcba9876543210",
                   "-ecc8a88064402010"));
    assert(cmp_3op(bignum_or, "-123456789abcdef0", "fedcba9876543210",
                   "-20446088a8ccf0"));
    assert(cmp_3op(bignum_or, "-123456789abcdef0", "-fedcba9876543210",
                   "-1214121812141210"));
    assert(cmp_3op(bignum_or, "123456789abcdef0123456789abcdef0", "77777777",
                   "123456789abcdef012345678fffffff7"));
    assert(cmp_3op(bignum_or, "123456789abcdef0123456789abcdef0", "-77777777",
                   "-65432107"));
    assert(cmp_3op(bignum_or, "-123456789abcdef0123456789abcdef0", "77777777",
                   "-123456789abcdef01234567888888889"));
    assert(cmp_3op(bignum_or, "-123456789abcdef0123456789abcdef0", "-77777777",
                   "-12345667"));

    bignum_t *u = bignum_from_hex("123456789abcdef0");
    bignum_t *w = bignum_or(u, u, u);

    assert(w == u);
    assert(bignum_eq(w, bignum_from_hex("123456789abcdef0")));
}

static void test_bignum_xor(void) {
    assert(cmp_3op(bignum_xor, "0", "0", "0"));
    assert(cmp_3op(bignum_xor, "1", "0", "1"));
    assert(cmp_3op(bignum_xor, "0", "1", "1"));
    assert(cmp_3op(bignum_xor, "1", "1", "0"));
    assert(cmp_3op(bignum_xor, "0", "-1", "-1"));
    assert(cmp_3op(bignum_xor, "-1", "0", "-1"));
    assert(cmp_3op(bignum_xor, "-1", "-1", "0"));
    assert(cmp_3op(bignum_xor, "-1", "1", "-2"));
    assert(cmp_3op(bignum_xor, "-80000000", "80000000", "-100000000"));
    assert(cmp_3op(bignum_xor, "-80000000", "FFFFFFFF80000000",
                   "-10000000000000000"));
    assert(cmp_3op(bignum_xor, "-8000000000000000", "8000000000000000",
                   "-10000000000000000"));
    assert(cmp_3op(bignum_xor, "-8000000000000000", "FFFFFFFF8000000000000000",
                   "-1000000000000000000000000"));
    assert(cmp_3op(bignum_xor, "123456789abcdef0", "fedcba9876543210",
                   "ece8ece0ece8ece0"));
    assert(cmp_3op(bignum_xor, "123456789abcdef0", "-fedcba9876543210",
                   "-ece8ece0ece8ed00"));
    assert(cmp_3op(bignum_xor, "-123456789abcdef0", "fedcba9876543210",
                   "-ece8ece0ece8ed00"));
    assert(cmp_3op(bignum_xor, "-123456789abcdef0", "-fedcba9876543210",
                   "ece8ece0ece8ece0"));
    assert(cmp_3op(bignum_xor, "123456789abcdef0123456789abcdef0", "77777777",
                   "123456789abcdef012345678edcba987"));
    assert(cmp_3op(bignum_xor, "123456789abcdef0123456789abcdef0", "-77777777",
                   "-123456789abcdef012345678edcba987"));
    assert(cmp_3op(bignum_xor, "-123456789abcdef0123456789abcdef0", "77777777",
                   "-123456789abcdef012345678edcba999"));
    assert(cmp_3op(bignum_xor, "-123456789abcdef0123456789abcdef0", "-77777777",
                   "123456789abcdef012345678edcba999"));

    bignum_t *u = bignum_from_hex("123456789abcdef0");
    bignum_t *w = bignum_xor(u, u, u);

    assert(w == u);
    assert(bignum_eq(w, bignum_from_hex("0")));
}

static void test_bignum_add(void) {
    assert(cmp_3op(bignum_add, "0", "0", "0"));
    assert(cmp_3op(bignum_add, "1", "0", "1"));
    assert(cmp_3op(bignum_add, "0", "1", "1"));
    assert(cmp_3op(bignum_add, "1", "1", "2"));
    assert(cmp_3op(bignum_add, "-1", "1", "0"));
    assert(cmp_3op(bignum_add, "1", "-1", "0"));
    assert(cmp_3op(bignum_add, "-1", "-1", "-2"));
    assert(cmp_3op(bignum_add, "0", "-1", "-1"));
    assert(cmp_3op(bignum_add, "-1", "0", "-1"));
    assert(cmp_3op(bignum_add, "ffffffff", "1", "100000000"));
    assert(cmp_3op(bignum_add, "ffffffff", "ffffffff", "1fffffffe"));
    assert(cmp_3op(bignum_add, "fffffffeffffffff", "1", "ffffffff00000000"));
    assert(cmp_3op(bignum_add, "ffffffffffffffff", "1", "10000000000000000"));
    assert(cmp_3op(bignum_add, "ffffffffffffffff", "ffffffffffffffff",
                   "1fffffffffffffffe"));

    bignum_t *u = bignum_from_hex("123456789abcdef0");
    bignum_t *w = bignum_add(u, u, u);

    assert(w == u);
    assert(bignum_eq(w, bignum_from_hex("2468acf13579bde0")));
}

static void test_bignum_sub(void) {
    assert(cmp_3op(bignum_sub, "0", "0", "0"));
    assert(cmp_3op(bignum_sub, "1", "0", "1"));
    assert(cmp_3op(bignum_sub, "0", "1", "-1"));
    assert(cmp_3op(bignum_sub, "1", "1", "0"));
    assert(cmp_3op(bignum_sub, "-1", "1", "-2"));
    assert(cmp_3op(bignum_sub, "1", "-1", "2"));
    assert(cmp_3op(bignum_sub, "-1", "-1", "0"));
    assert(cmp_3op(bignum_sub, "0", "-1", "1"));
    assert(cmp_3op(bignum_sub, "-1", "0", "-1"));
    assert(cmp_3op(bignum_sub, "1", "2", "-1"));
    assert(cmp_3op(bignum_sub, "-1", "-2", "1"));
    assert(cmp_3op(bignum_sub, "100000000", "1", "ffffffff"));
    assert(cmp_3op(bignum_sub, "100000000", "ffffffff", "1"));
    assert(cmp_3op(bignum_sub, "10000000100000000", "1", "100000000ffffffff"));
    assert(cmp_3op(bignum_sub, "10000000000000000", "1", "ffffffffffffffff"));
    assert(cmp_3op(bignum_sub, "10000000000000000", "ffffffffffffffff", "1"));

    bignum_t *u = bignum_from_hex("123456789abcdef0");
    bignum_t *v = bignum_from_hex("123456789abcdeef");
    bignum_t *w = bignum_sub(u, u, v);

    assert(w == u);
    assert(bignum_eq(w, bignum_from_hex("1")));
}

static void test_bignum_mul(void) {
    assert(cmp_3op(bignum_mul, "0", "0", "0"));
    assert(cmp_3op(bignum_mul, "1", "0", "0"));
    assert(cmp_3op(bignum_mul, "0", "1", "0"));
    assert(cmp_3op(bignum_mul, "1", "1", "1"));
    assert(cmp_3op(bignum_mul, "-1", "1", "-1"));
    assert(cmp_3op(bignum_mul, "1", "-1", "-1"));
    assert(cmp_3op(bignum_mul, "-1", "-1", "1"));
    assert(cmp_3op(bignum_mul, "0", "-1", "0"));
    assert(cmp_3op(bignum_mul, "ffffffff", "1", "ffffffff"));
    assert(cmp_3op(bignum_mul, "ffffffff", "ffffffff", "fffffffe00000001"));

    bignum_t *u = bignum_from_hex("123456789abcdef0");
    bignum_t *w = bignum_mul(u, u, u);

    assert(w == u);
    assert(bignum_eq(w, bignum_from_hex("14b66dc33f6acdca5e20890f2a52100")));
}

static void test_bignum_div(void) {
    assert(cmp_div(bignum_div, "0", "0", NULL, NULL));
    assert(cmp_div(bignum_div, "1", "0", NULL, NULL));
    assert(cmp_div(bignum_div, "0", "1", "0", "0"));
    assert(cmp_div(bignum_div, "1", "1", "1", "0"));
    assert(cmp_div(bignum_div, "-1", "1", "-1", "0"));
    assert(cmp_div(bignum_div, "1", "-1", "-1", "0"));
    assert(cmp_div(bignum_div, "-1", "-1", "1", "0"));
    assert(cmp_div(bignum_div, "-1", "2", "0", "-1"));
    assert(cmp_div(bignum_div, "2", "-1", "-2", "0"));
    assert(cmp_div(bignum_div, "3", "3", "1", "0"));
    assert(cmp_div(bignum_div, "3", "4", "0", "3"));
    assert(cmp_div(bignum_div, "0", "ffffffff", "0", "0"));
    assert(cmp_div(bignum_div, "ffffffff", "1", "ffffffff", "0"));
    assert(cmp_div(bignum_div, "ffffffff", "ffffffff", "1", "0"));
    assert(cmp_div(bignum_div, "ffffffff", "3", "55555555", "0"));
    assert(
        cmp_div(bignum_div, "ffffffffffffffff", "1", "ffffffffffffffff", "0"));
    assert(
        cmp_div(bignum_div, "ffffffffffffffff", "ffffffff", "100000001", "0"));
    assert(cmp_div(bignum_div, "fffffffeffffffff", "ffffffff", "0ffffffff",
                   "fffffffe"));
    assert(cmp_div(bignum_div, "123400005678", "9abc", "1e1dba76", "6bd0"));
    assert(cmp_div(bignum_div, "0", "100000000", "0", "0"));
    assert(cmp_div(bignum_div, "700000000", "300000000", "2", "100000000"));
    assert(cmp_div(bignum_div, "700000005", "300000000", "2", "100000005"));
    assert(cmp_div(bignum_div, "600000000", "200000000", "3", "0"));
    assert(cmp_div(bignum_div, "80000000", "40000001", "1", "3fffffff"));
    assert(
        cmp_div(bignum_div, "8000000000000000", "40000001", "1fffffff8", "8"));
    assert(cmp_div(bignum_div, "8000000000000000", "4000000000000001", "1",
                   "3fffffffffffffff"));
    assert(cmp_div(bignum_div, "bcde0000789a", "bcde0000789a", "1", "0"));
    assert(cmp_div(bignum_div, "bcde0000789b", "bcde0000789a", "1", "1"));
    assert(cmp_div(bignum_div, "bcde00007899", "bcde0000789a", "0",
                   "bcde00007899"));
    assert(cmp_div(bignum_div, "ffff0000ffff", "ffff0000ffff", "1", "0"));
    assert(cmp_div(bignum_div, "ffff0000ffff", "100000000", "ffff", "0ffff"));
    assert(cmp_div(bignum_div, "12300004567000089ab", "100000000",
                   "12300004567", "89ab"));
    assert(cmp_div(bignum_div, "80000000fffe00000000", "80000000ffff",
                   "0ffffffff", "7fff0000ffff"));
    assert(cmp_div(bignum_div, "800000000000000000000003",
                   "200000000000000000000001", "3",
                   "200000000000000000000000"));
    assert(cmp_div(bignum_div, "80000000000000000003", "20000000000000000001",
                   "3", "20000000000000000000"));
    assert(cmp_div(bignum_div, "7fff000080000000000000000000",
                   "80000000000000000001", "0fffe0000",
                   "7fffffffffff00020000"));
    assert(cmp_div(bignum_div, "8000000000000000fffe00000000",
                   "8000000000000000ffff", "0ffffffff",
                   "7fffffffffff0000ffff"));
    assert(cmp_div(bignum_div, "8000000000000000fffffffe00000000",
                   "80000000000000000000ffff", "100000000",
                   "0fffeffff00000000"));
    assert(cmp_div(bignum_div, "8000000000000000fffffffe00000000",
                   "8000000000000000ffffffff", "0ffffffff",
                   "7fffffffffffffffffffffff"));
    assert(cmp_div(
        bignum_div, "1321d2fddde8bd9dff379aff030de205b846eb5cecc40fa8aa9c2a85ce"
                    "3e992193e873b2bc667dabe2ac3ee9dd23b3a9ed9ec0c3c7445663f545"
                    "5469b727dd6fbc03b1bf95d03a13c0368645767630c7eabf5e7ab5fa27"
                    "b94ade7e1e23bcc65d2a7ded1c5b364b51",
        "12345678", "10d0ba71aef7bf6e2c89ba629c41e3ed3726663d00deb6c9c5585312a7"
                    "b3c6b5147766b3458cfd67e167cd3e874eb17bd7f56c08bdc9263827bf"
                    "b40e3bd7841830e722070258a446efe1605e041993fed82b9c0007638a"
                    "ea199ba99e57140c19c68314410",
        "40103d1"));
    assert(cmp_div(
        bignum_div, "1321d2fddde8bd9dff379aff030de205b846eb5cecc40fa8aa9c2a85ce"
                    "3e992193e873b2bc667dabe2ac3ee9dd23b3a9ed9ec0c3c7445663f545"
                    "5469b727dd6fbc03b1bf95d03a13c0368645767630c7eabf5e7ab5fa27"
                    "b94ade7e1e23bcc65d2a7ded1c5b364b51",
        "cafebabe", "1820b7ac4b102c8e5abcee354aa01897970afb34b8c329612f3cccfc6f"
                    "2c094447e9f6aa9ffe5bc75069dbea8b80d56bc330a82974654a35aaff"
                    "7d458d514a1ebaba6853b4bc6505b31e05372d2cdfa9a80e659b82c0aa"
                    "0202fd5283cc0bd090bc4d7c31",
        "6ada84f3"));
    assert(cmp_div(bignum_div,
                   "1321d2fddde8bd9dff379aff030de205b846eb5cecc40fa8aa9c2a85ce"
                   "3e992193e873b2bc667dabe2ac3ee9dd23b3a9ed9ec0c3c7445663f545"
                   "5469b727dd6fbc03b1bf95d03a13c0368645767630c7eabf5e7ab5fa27"
                   "b94ade7e1e23bcc65d2a7ded1c5b364b51",
                   "6104faf81f41fdd7616b4378f6bd991292cb2f21c10d06c5e8e571a5e9"
                   "62b7e82dfd9fe7120f6d03a86cc6bbc7dd3a6280839ef7",
                   "327b9fda4b211e3bfdb54f680e5c04528aaa20428ae008faf48df6c913"
                   "f5747d8608a5a48e2bfe41fae7a04683f2305852cdadf7",
                   "0"));

    bignum_t *u = bignum_from_hex("123456789abcdef0123456789abcdef0");
    bignum_t *v = bignum_from_hex("fedcba9876543210");
    bignum_qr_t qr = bignum_div(u, v, u, v);

    assert(qr.quotient == u);
    assert(qr.remainder == v);
    assert(bignum_eq(u, bignum_from_hex("1249249249249237")));
    assert(bignum_eq(v, bignum_from_hex("fd8fd8fd8fd8fd80")));
}

int main(int argc, char const *argv[]) {
    printf("run unittest_%d\n----\n", BIGNUM_INT_BITS);

    RUN(test_bignum_0);
    RUN(test_bignum_from_int);
    RUN(test_bignum_from_uint);
    RUN(test_bignum_from_hex);
    RUN(test_bignum_from);
    RUN(test_bignum_neg);
    RUN(test_bignum_abs);
    RUN(test_bignum_not);
    RUN(test_bignum_shl);
    RUN(test_bignum_shr);
    RUN(test_bignum_and);
    RUN(test_bignum_or);
    RUN(test_bignum_xor);
    RUN(test_bignum_add);
    RUN(test_bignum_sub);
    RUN(test_bignum_mul);
    RUN(test_bignum_div);

    return 0;
}
