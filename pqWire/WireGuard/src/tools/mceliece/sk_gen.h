/*
  This file is for secret-key generation
*/

#ifndef MC_TOOL_SK_GEN_H
#define MC_TOOL_SK_GEN_H

#include "gf.h"

#include <stdint.h>

int genpoly_gen(gf *, gf *);
int perm_check(uint32_t *);

#endif

