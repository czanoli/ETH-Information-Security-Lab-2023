#ifndef ___ECC_FUNCTIONS___
#define ___ECC_FUNCTIONS___
#include <gmp.h>

/*
 * Curve holds all data related to the curve.
 */
typedef struct Curve {
    mpz_t p;
    mpz_t a;
    mpz_t b;
    mpz_t x;
    mpz_t y;
    mpz_t q;

} Curve;

/*
 * Point describes a point on the curve.
 */
typedef struct Point {
    mpz_t x, y;
    int infinity;
} Point;

static void pointdouble(Point *p, Curve *cu);
static void pointaddition(Point *point1, Point *point2, Curve *cu);

#endif
