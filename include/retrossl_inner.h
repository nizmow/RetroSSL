#ifndef RETROSSL_INNER_H__
#define RETROSSL_INNER_H__

#include <stdint.h>

#define NOT(ctl) ((ctl) ^ 1)
#define LT0(x) ((x) >> 31)
#define GT(x, y) LT0((y) - (x))

#define EQ(x, y) NOT(((x) ^ (y)) | (((uint32_t)0 - ((x) ^ (y)))))
#define NEQ(x, y) (((x) ^ (y)) | (((uint32_t)0 - ((x) ^ (y))))) >> 31
#define MUX(ctl, x, y) ((y) ^ (((uint32_t)0 - (ctl)) & ((x) ^ (y))))

#endif
