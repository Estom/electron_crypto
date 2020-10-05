/*************************************************************************
        > File Name: sm2_test_param.h
        > Author:NEWPLAN
        > E-mail:newplan001@163.com
        > Created Time: Thu Apr 13 23:55:50 2017
 ************************************************************************/
#include"sm2_common.h"
#ifndef SM2_TEST_PARAM_H
#define SM2_TEST_PARAM_H

#define MES_LEN 2000

extern char* sm2_param_recommand[];

extern char* sm2_param_fp_192[];
extern char* sm2_param_fp_256[];
extern char* sm2_param_f2m_193[];
extern char* sm2_param_f2m_257[];

extern char* sm2_param_digest_d_A[2];
extern char* sm2_param_digest_k[2];

extern char* sm2_param_dh_d_A[2];
extern char* sm2_param_dh_r_A[2];
extern char* sm2_param_dh_d_B[2];
extern char* sm2_param_dh_r_B[2];
extern int sm2_param_dh_h[2];

extern char* sm2_param_d_B[2];
extern char* sm2_param_k[2];

extern char message[MES_LEN];
extern char* message_digest;

extern char* ID_A;
extern char* ID_B;


extern ec_param* ecp;
extern ec_param* ecp2;
extern sm2_ec_key* key_A;
extern sm2_ec_key* key_B;

#endif
