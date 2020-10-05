#ifndef PART5_H
#define PART5_H

#include "sm2_common.h"
#include "xy_ecpoint.h"
#include "sm2_ec_key.h"
#include "util.h"
#include "sm2_test_param.h"
#include<time.h>
#include "ec_param.h"

#define TIMESTAMP_LEN 20 //时间戳的长度
#define MAX_TIME_DIF 10//最大时间差距，单位秒

typedef struct
{
	BYTE* message;
	int message_byte_length;
	//BYTE *encrypt;
	BYTE *decrypt;
	int klen_bit;

	BYTE k[MAX_POINT_BYTE_LENGTH]; //随机数
	BYTE private_key[MAX_POINT_BYTE_LENGTH];
	struct
	{
		BYTE x[MAX_POINT_BYTE_LENGTH];
		BYTE y[MAX_POINT_BYTE_LENGTH];
	} public_key;

	BYTE C[1024]; // C_1 || C_2 || C_3
	BYTE C_1[1024];
	BYTE C_2[1024]; //加密后的消息
	BYTE C_3[1024];
} message_st;

typedef struct
{
	BYTE* message;
	int message_byte_length;
	BYTE* ID;
	int ENTL;
	BYTE k[MAX_POINT_BYTE_LENGTH]; //签名中产生随机数
	BYTE private_key[MAX_POINT_BYTE_LENGTH];
	struct
	{
		BYTE x[MAX_POINT_BYTE_LENGTH];
		BYTE y[MAX_POINT_BYTE_LENGTH];
	} public_key;
	BYTE Z[HASH_BYTE_LENGTH];
	BYTE r[MAX_POINT_BYTE_LENGTH];
	BYTE s[MAX_POINT_BYTE_LENGTH];
	BYTE R[MAX_POINT_BYTE_LENGTH];
} sm2_sign_st;

int sm2_encrypt_copy(ec_param* ecp, message_st* message_data); //加密函数
int sm2_decrypt_copy(ec_param* ecp, message_st* message_data);//解密函数
void sm2_sign_modified(ec_param* ecp, sm2_sign_st* sign, message_st* message_data);//签名函数
void sm2_verify_modified(ec_param* ecp, sm2_sign_st* sign, message_st* message_data);//解签名函数

//字符串时间和time_t时间转换函数
void time_t2string(const time_t time_t_time, char* time_now);
time_t string2time_t(const char* string_time);

int C3_is_equal(BYTE* cipher_C3, BYTE* local_C_3);//比较C3是否相等。
#endif
