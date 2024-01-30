#include "ecc.h"

#include <fcntl.h>
#include <gmp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define PAGE_ALIGN __attribute__((aligned(4096))) __attribute__((noinline))
#define unlikely(x) __builtin_expect(!!(x), 0)

static inline __attribute__((always_inline)) void add(mpz_t a, mpz_t b, mpz_t n) {
    mpz_add(a, a, b);
    mpz_mod(a, a, n);
}

static inline __attribute__((always_inline)) void sub(mpz_t a, mpz_t b, mpz_t n) {
    mpz_sub(a, a, b);
    mpz_mod(a, a, n);
}

static inline __attribute__((always_inline)) void mul(mpz_t a, mpz_t b, mpz_t n) {
    mpz_mul(a, a, b);
    mpz_mod(a, a, n);
}

static inline __attribute__((always_inline)) void calc_inv(mpz_t a, mpz_t n, mpz_t inverse) {
    mpz_invert(inverse, a, n);
}

static void PAGE_ALIGN pointaddition(Point *point1, Point *point2, Curve *cu) {
    mpz_t s, p1, x3, y3;
    if (unlikely(point2->infinity == 1)) {
        return;
    }
    if (unlikely(point1->infinity == 1)) {
        point1->infinity = 0;
        mpz_set(point1->x, point2->x);
        mpz_set(point1->y, point2->y);
        return;
    }
    mpz_init(s);
    if (unlikely(mpz_cmp(point1->x, point2->x) == 0)) {
        mpz_neg(s, point1->y);
        mpz_mod(s, s, cu->p);
        if (mpz_cmp(s, point2->y) == 0) {
            point1->infinity = 1;
            mpz_clear(s);
            return;
        } else {
            pointdouble(point1, cu);
            return;
        }
    }

    mpz_inits(p1, x3, y3, NULL);
    mpz_sub(p1, point2->y, point1->y);
    mpz_sub(s, point2->x, point1->x);
    calc_inv(s, cu->p, s);
    mul(s, p1, cu->p);

    mpz_mul(p1, s, s);
    sub(p1, point1->x, cu->p);
    sub(p1, point2->x, cu->p);
    mpz_set(x3, p1);

    mpz_sub(p1, point1->x, x3);
    mul(p1, s, cu->p);
    mpz_sub(y3, p1, point1->y);

    mpz_mod(y3, y3, cu->p);
    mpz_mod(x3, x3, cu->p);

    mpz_set(point1->x, x3);
    mpz_set(point1->y, y3);
    mpz_clears(s, p1, x3, y3, NULL);
}

static void PAGE_ALIGN pointdouble(Point *p, Curve *cu) {
    mpz_t s, p1, x3, y3;
    if (mpz_cmp_d(p->y, 0) == 0) {
        p->infinity = 1;
        return;
    }
    mpz_inits(s, p1, x3, y3, NULL);

    mpz_mul(p1, p->x, p->x);
    mpz_mul_ui(p1, p1, 3);
    add(p1, cu->a, cu->p);

    mpz_mul_ui(s, p->y, 2);
    calc_inv(s, cu->p, s);
    mul(s, p1, cu->p);

    //* compute s
    mpz_pow_ui(p1, s, 2);
    sub(p1, p->x, cu->p);
    sub(p1, p->x, cu->p);
    mpz_set(x3, p1);

    mpz_sub(p1, p->x, x3);
    mul(p1, s, cu->p);
    mpz_sub(y3, p1, p->y);

    mpz_mod(y3, y3, cu->p);
    mpz_mod(x3, x3, cu->p);

    mpz_set(p->x, x3);
    mpz_set(p->y, y3);
    mpz_clears(s, p1, x3, y3, NULL);
}

static void PAGE_ALIGN doubleandadd(mpz_t factor, Point *ret_p, Curve *cu) {
    mpz_mod(factor, factor, cu->q);
    int range = mpz_sizeinbase(factor, 2);
    Point tmp_p = {.infinity = 0};

    mpz_init_set(tmp_p.x, cu->x);
    mpz_init_set(tmp_p.y, cu->y);
    mpz_init_set(ret_p->x, cu->x);
    mpz_init_set(ret_p->y, cu->y);

    for (int i = range - 2; i >= 0; --i) {
        pointdouble(ret_p, cu);
        if (mpz_tstbit(factor, i)) {
            pointaddition(ret_p, &tmp_p, cu);
        }
    }
}

/*
 * brainpoolP256r1
 */
static void PAGE_ALIGN initCruve(Curve *a) {
    mpz_init_set_str(a->a, "7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9", 16);
    mpz_init_set_str(a->p, "A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377", 16);
    mpz_init_set_str(a->b, "26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6", 16);
    mpz_init_set_str(a->q, "A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7", 16);
    mpz_init_set_str(a->x, "8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262", 16);
    mpz_init_set_str(a->y, "547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997", 16);
}

static void PAGE_ALIGN free_curve(Curve *a) {
    mpz_clears(a->a, a->p, a->x, a->y, a->b, a->q, NULL);
}

void PAGE_ALIGN compute_dh_pubkey(Curve *curve, char *privkey) {
    mpz_t factor;
    Point pub_key_point = {.infinity = 0};

    mpz_init_set_str(factor, privkey, 16);
    mpz_inits(pub_key_point.x, pub_key_point.y, NULL);
    mpz_set(pub_key_point.x, curve->x);
    mpz_set(pub_key_point.y, curve->y);
    doubleandadd(factor, &pub_key_point, curve);
    gmp_printf("DH Pubkey:\n%ZX\n%ZX\n", pub_key_point.x, pub_key_point.y);
    mpz_clears(factor, pub_key_point.x, pub_key_point.y, NULL);
}

int PAGE_ALIGN main(int argc, char *argv[]) {
    Curve curve;
    if (argc != 2) {
        exit(-1);
    }
    initCruve(&curve);
    compute_dh_pubkey(&curve, argv[1]);
    free_curve(&curve);
    return 0;
}
