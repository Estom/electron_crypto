#ifndef PART5_H
#define PART5_H

#include "sm2.h"

void test_part5(char **sm2_param, int type, int point_bit_length);
void test_part5_enc_sig(char **sm2_param, int type, int point_bit_length);
void test_part5_ver_dec(char **sm2_param, int type, int point_bit_length);
// return signature bytes
#endif
