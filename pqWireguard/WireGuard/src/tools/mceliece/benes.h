/*
  This file is for Benes network related functions
*/

#ifndef MC_TOOL_BENES_H
#define MC_TOOL_BENES_H

#include "vec128.h"

void load_bits(vec128 [][32], const unsigned char *);
void benes(vec128 *, vec128 [][32], int);

#endif

