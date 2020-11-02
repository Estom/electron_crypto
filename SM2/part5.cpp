/*************************************************************************
		> File Name: part4.c
		> Author:NEWPLAN
		> E-mail:newplan001@163.com
		> Created Time: Thu Apr 13 23:55:50 2017
 ************************************************************************/

#include "sm2_ec_key.h"
#include<time.h>

// encrypt-decrypt
#include "part5.h"

const int PRINT_MESSAGE = 0;
#define TIMES 1000

/*sm2加密信息*/
int sm2_encrypt_copy(ec_param* ecp, message_st* message_data)
{
	BIGNUM* P_x;
	BIGNUM* P_y;
	//BIGNUM *d;
	BIGNUM* k;
	xy_ecpoint* P;
	xy_ecpoint* xy1;
	xy_ecpoint* xy2;
	int pos1;
	BYTE* t;
	int i;
	sm2_hash local_C_3;

	P_x = BN_new();
	P_y = BN_new();
	k = BN_new();
	P = xy_ecpoint_new(ecp);
	xy1 = xy_ecpoint_new(ecp);
	xy2 = xy_ecpoint_new(ecp);

	BN_bin2bn(message_data->public_key.x, ecp->point_byte_length, P_x);
	BN_bin2bn(message_data->public_key.y, ecp->point_byte_length, P_y);
	BN_bin2bn(message_data->k, ecp->point_byte_length, k);

	show_bignum(P_x,ecp->point_byte_length);
	show_bignum(P_y,ecp->point_byte_length);
	printf("\n");
	xy_ecpoint_init_xy(P, P_x, P_y, ecp);
	show_bignum(P->x,ecp->point_byte_length);
	show_bignum(P->y,ecp->point_byte_length);
	xy_ecpoint_mul_bignum(xy1, ecp->G, k, ecp);
	xy_ecpoint_mul_bignum(xy2, P, k, ecp);

	pos1 = 0;
	message_data->C_1[0] = '\x04';
	pos1 = pos1 + 1;
	BUFFER_APPEND_BIGNUM(message_data->C_1, pos1, ecp->point_byte_length, xy1->x);
	BUFFER_APPEND_BIGNUM(message_data->C_1, pos1, ecp->point_byte_length, xy1->y);

	pos1 = 0;
	BUFFER_APPEND_BIGNUM(message_data->C_2, pos1, ecp->point_byte_length, xy2->x);
	BUFFER_APPEND_BIGNUM(message_data->C_2, pos1, ecp->point_byte_length, xy2->y);
	printf("\n");
	show_bignum(xy2->x,ecp->point_byte_length);
	show_bignum(xy2->y,ecp->point_byte_length);

	t = KDF((BYTE*)message_data->C_2, message_data->klen_bit, ecp->point_byte_length + ecp->point_byte_length);
	//加密过程
	for (i = 0; i < message_data->message_byte_length; i++)
	{
		printf("%d ",t[i]);
		message_data->C_2[i] = t[i] ^ message_data->message[i];
	}
	//lzd:长度限制一，因为C_2的最大长度值1024
	OPENSSL_free(t);

	//计算C_3
	memset(&local_C_3, 0, sizeof(local_C_3));
	BUFFER_APPEND_BIGNUM(local_C_3.buffer, local_C_3.position, ecp->point_byte_length, xy2->x);
	BUFFER_APPEND_STRING(local_C_3.buffer, local_C_3.position, message_data->message_byte_length, message_data->message);
	BUFFER_APPEND_BIGNUM(local_C_3.buffer, local_C_3.position, ecp->point_byte_length, xy2->y);
	//lzd：长度限制之二，local_C_3.buffer的长度为1024，xy2->x，xy->y的长度得使用sizeof获得。
	SM3_Init();
	SM3_Update((BYTE*)local_C_3.buffer, local_C_3.position);
	SM3_Final_byte(local_C_3.hash);
	memcpy(message_data->C_3, (char*)local_C_3.hash, HASH_BYTE_LENGTH);

	pos1 = 0;
	BUFFER_APPEND_STRING(message_data->C, pos1, 1 + ecp->point_byte_length + ecp->point_byte_length, message_data->C_1);
	BUFFER_APPEND_STRING(message_data->C, pos1, message_data->message_byte_length, message_data->C_2);
	BUFFER_APPEND_STRING(message_data->C, pos1, HASH_BYTE_LENGTH, message_data->C_3);
	//lzd：明文长度限制


	if (PRINT_MESSAGE) {
		printf("encrypt: \n");
		DEFINE_SHOW_STRING(message_data->C_2, message_data->message_byte_length);
	}

	BN_free(P_x);
	BN_free(P_y);
	BN_free(k);
	xy_ecpoint_free(P);
	xy_ecpoint_free(xy1);
	xy_ecpoint_free(xy2);

	return pos1;
}

int sm2_decrypt_copy(ec_param* ecp, message_st* message_data,bool* flag_replay_attack,bool* flag_tamper_attack)
{
	time_t time_NOW;//解密时的时间
	time_t time_PREV;//明文中包含的时间
	char time_prev[TIMESTAMP_LEN] = { '\0' };//明文中包含时间的字符串格式
	int pos1;
	int pos2;
	xy_ecpoint* xy1;
	xy_ecpoint* xy2;
	BIGNUM* d;
	BYTE KDF_buffer[MAX_POINT_BYTE_LENGTH * 2];
	BYTE* t;
	sm2_hash local_C_3;//计算u，判断是否与加密中计算的C3相等。
	int i;

	*flag_replay_attack = false;
	*flag_tamper_attack = false;

	xy1 = xy_ecpoint_new(ecp);
	xy2 = xy_ecpoint_new(ecp);
	d = BN_new();


	BN_bin2bn(&message_data->C_1[1], ecp->point_byte_length, xy1->x);
	BN_bin2bn(&message_data->C_1[1 + ecp->point_byte_length], ecp->point_byte_length, xy1->y);
	printf("%d\n",ecp->point_byte_length);

	BN_bin2bn(message_data->private_key, ecp->point_byte_length, d);
	xy_ecpoint_init_xy(xy1, xy1->x, xy1->y, ecp);
	xy_ecpoint_mul_bignum(xy2, xy1, d, ecp);

	//C_1是否是无穷远点.如果是，则退出。
	try {
		if (EC_POINT_is_on_curve(ecp->group, xy1->ec_point, ecp->ctx) == 0)
			throw true;
	}
	catch (bool flag) {
		printf("C1不满足椭圆曲线方程，所以C1被修改，解签密失败\n");
		*flag_tamper_attack = flag;
		xy_ecpoint_free(xy1);
		xy_ecpoint_free(xy2);
		BN_free(d);
		return 0;
	}

	pos1 = 0;
	memset(KDF_buffer, 0, sizeof(KDF_buffer));
	BUFFER_APPEND_BIGNUM(KDF_buffer, pos1, ecp->point_byte_length, xy2->x);
	BUFFER_APPEND_BIGNUM(KDF_buffer, pos1, ecp->point_byte_length, xy2->y);
	if (PRINT_MESSAGE) {
		DEFINE_SHOW_BIGNUM(d);
		DEFINE_SHOW_BIGNUM(xy2->x);
		DEFINE_SHOW_BIGNUM(xy2->y);
	}
	t = KDF((BYTE*)KDF_buffer, message_data->klen_bit, ecp->point_byte_length + ecp->point_byte_length);
	//解密过程
	printf("%d\n",message_data->message_byte_length);
	for (i = 0; i < message_data->message_byte_length; i++)
	{
		printf("%d ",message_data->C_2[i]);
		message_data->decrypt[i] = t[i] ^ message_data->C_2[i];
	}
	OPENSSL_free(t);

	//计算C_3,并与密文中的C3相比较。
	memset(&local_C_3, 0, sizeof(local_C_3));
	BUFFER_APPEND_BIGNUM(local_C_3.buffer, local_C_3.position, ecp->point_byte_length, xy2->x);
	BUFFER_APPEND_STRING(local_C_3.buffer, local_C_3.position, message_data->message_byte_length, message_data->decrypt);
	BUFFER_APPEND_BIGNUM(local_C_3.buffer, local_C_3.position, ecp->point_byte_length, xy2->y);
	SM3_Init();
	SM3_Update((BYTE*)local_C_3.buffer, local_C_3.position);
	SM3_Final_byte(local_C_3.hash);

	try 
	{
		if (C3_is_equal(message_data->C_3, local_C_3.hash) == 0)
			throw true;
	}
	catch (bool flag)
	{
		xy_ecpoint_free(xy1);
		xy_ecpoint_free(xy2);
		BN_free(d);
		printf("C3被篡改，解签密失败\n");
		*flag_tamper_attack = flag;
		return 0;
	}

	//计算时间满足要求，如果超过一分钟，退出程序。
	memcpy(time_prev, &message_data->decrypt[message_data->message_byte_length - TIMESTAMP_LEN+1], TIMESTAMP_LEN);
	time_NOW = time(NULL);
	char time_now[TIMESTAMP_LEN] = {'\0'};
	time_t2string(time_NOW, time_now);
	time_PREV = string2time_t(time_prev);
	try {
		if ((time_NOW - time_PREV) >= MAX_TIME_DIF)
			throw true;
	}
	catch (bool flag)
	{
		xy_ecpoint_free(xy1);
		xy_ecpoint_free(xy2);
		BN_free(d);
		printf("当前时间: %s\n", time_now);
		printf("密文解密出的时间戳: %s\n", time_prev);
		printf("两者时间相差过大，解签密失败\n");
		*flag_replay_attack = flag;
		return 0;
	}

	xy_ecpoint_free(xy1);
	xy_ecpoint_free(xy2);
	BN_free(d);

	return SUCCESS;
}

void sm2_sign_modified(ec_param* ecp, sm2_sign_st* sign, message_st* message_data)
{
	sm2_hash Z_A;
	sm2_hash e;
	BIGNUM* e_bn;

	BIGNUM* r;
	BIGNUM* s;
	BIGNUM* tmp1;

	BIGNUM* P_x;
	BIGNUM* P_y;
	BIGNUM* d;
	BIGNUM* k;
	xy_ecpoint* xy1;

	e_bn = BN_new();
	r = BN_new();
	s = BN_new();
	tmp1 = BN_new();
	P_x = BN_new();
	P_y = BN_new();
	d = BN_new();
	k = BN_new();
	xy1 = xy_ecpoint_new(ecp);

	BN_bin2bn(sign->public_key.x, ecp->point_byte_length, P_x);
	BN_bin2bn(sign->public_key.y, ecp->point_byte_length, P_y);
	BN_bin2bn(sign->private_key, ecp->point_byte_length, d);
	BN_bin2bn(sign->k, ecp->point_byte_length, k);

	//lzd:加上杂凑函数，hash值为HASH_BYTE_LENGTH字节
	BYTE e_hash[HASH_BYTE_LENGTH];
	SM3_Init();
	SM3_Update((BYTE*)message_data->C_2, message_data->message_byte_length);
	SM3_Final_byte(e_hash);
	BN_bin2bn(e_hash, HASH_BYTE_LENGTH, e_bn);

	xy_ecpoint_mul_bignum(xy1, ecp->G, k, ecp);
	BN_zero(r);
	BN_mod_add(r, e_bn, xy1->x, ecp->n, ecp->ctx);

	BN_one(s);
	BN_add(s, s, d);
	BN_mod_inverse(s, s, ecp->n, ecp->ctx); //求模反

	BN_mul(tmp1, r, d, ecp->ctx);
	BN_sub(tmp1, k, tmp1);
	BN_mod_mul(s, s, tmp1, ecp->n, ecp->ctx);

	sm2_bn2bin(r, sign->r, ecp->point_byte_length);
	sm2_bn2bin(s, sign->s, ecp->point_byte_length);

	if (PRINT_MESSAGE) {
		DEFINE_SHOW_BIGNUM(r);
		DEFINE_SHOW_BIGNUM(s);
	}

	BN_free(e_bn);
	BN_free(r);
	BN_free(s);
	BN_free(tmp1);
	BN_free(P_x);
	BN_free(P_y);
	BN_free(d);
	BN_free(k);
	xy_ecpoint_free(xy1);
}

void sm2_verify_modified(ec_param* ecp, sm2_sign_st* sign, message_st* message_data, bool* flag_tamper_attack)
{
	sm2_hash e;
	BIGNUM* e_bn;
	BIGNUM* t;
	BIGNUM* R;
	xy_ecpoint* result;
	xy_ecpoint* result1;
	xy_ecpoint* result2;
	xy_ecpoint* P_A;
	BIGNUM* r;
	BIGNUM* s;
	BIGNUM* P_x;
	BIGNUM* P_y;

	*flag_tamper_attack = false;

	e_bn = BN_new();
	t = BN_new();
	R = BN_new();
	result = xy_ecpoint_new(ecp);
	result1 = xy_ecpoint_new(ecp);
	result2 = xy_ecpoint_new(ecp);
	P_A = xy_ecpoint_new(ecp);
	r = BN_new();
	s = BN_new();
	P_x = BN_new();
	P_y = BN_new();

	BN_bin2bn(sign->r, ecp->point_byte_length, r);
	BN_bin2bn(sign->s, ecp->point_byte_length, s);
	BN_bin2bn(sign->public_key.x, ecp->point_byte_length, P_x);
	BN_bin2bn(sign->public_key.y, ecp->point_byte_length, P_y);
	xy_ecpoint_init_xy(P_A, P_x, P_y, ecp);

	//lzd:加上杂凑函数，hash值为HASH_BYTE_LENGTH字节
	BYTE e_hash[HASH_BYTE_LENGTH];
	SM3_Init();
	SM3_Update((BYTE*)message_data->C_2, message_data->message_byte_length);
	SM3_Final_byte(e_hash);
	BN_bin2bn(e_hash, HASH_BYTE_LENGTH, e_bn);

	if (PRINT_MESSAGE)
		DEFINE_SHOW_BIGNUM(e_bn);

	BN_mod_add(t, r, s, ecp->n, ecp->ctx);
	xy_ecpoint_mul_bignum(result1, ecp->G, s, ecp);
	xy_ecpoint_mul_bignum(result2, P_A, t, ecp);
	xy_ecpoint_add_xy_ecpoint(result, result1, result2, ecp);

	BN_mod_add(R, e_bn, result->x, ecp->n, ecp->ctx);

	sm2_bn2bin(R, sign->R, ecp->point_byte_length);

	if (PRINT_MESSAGE)
		DEFINE_SHOW_STRING(sign->R, ecp->point_byte_length);

	//R和r是否相等。
	for (int i = 0; i < ecp->point_byte_length; i++)
	{
		try {
			if (sign->R[i] != sign->r[i])
				throw true;
		}
		catch (bool flag)
		{
			BN_free(e_bn);
			BN_free(t);
			BN_free(R);
			xy_ecpoint_free(result);
			xy_ecpoint_free(result1);
			xy_ecpoint_free(result2);
			xy_ecpoint_free(P_A);
			BN_free(r);
			BN_free(s);
			BN_free(P_x);
			BN_free(P_y);
			printf("解签密失败\n");
			*flag_tamper_attack = flag;
			return;
		}
	}


	BN_free(e_bn);
	BN_free(t);
	BN_free(R);
	xy_ecpoint_free(result);
	xy_ecpoint_free(result1);
	xy_ecpoint_free(result2);
	xy_ecpoint_free(P_A);
	BN_free(r);
	BN_free(s);
	BN_free(P_x);
	BN_free(P_y);
}

//lzd:将字符串时间转换成time_t时间，字符串时间格式为YYYY/MM/DD HH:MM:SS
time_t string2time_t(const char* string_time)
{
	tm tm1;
	memset(&tm1, 0, sizeof(tm1));
	time_t time1;

	sscanf(string_time, "%d/%d/%d %d:%d:%d",
		&(tm1.tm_year),
		&(tm1.tm_mon),
		&(tm1.tm_mday),
		&(tm1.tm_hour),
		&(tm1.tm_min),
		&(tm1.tm_sec));

	tm1.tm_year -= 1900;
	tm1.tm_mon -= 1;

	time1 = mktime(&tm1);

	return time1;

}

void time_t2string(const time_t time_t_time, char* time_now)
{
	char szTime[TIMESTAMP_LEN] = { '\0' };
	tm* pTm = new tm;
	pTm=localtime(&time_t_time);
	//pTm = localtime(&time_t_time);
	pTm->tm_year += 1900;
	pTm->tm_mon += 1;

	sprintf(szTime, "%04d/%02d/%02d %02d:%02d:%02d",
		pTm->tm_year,
		pTm->tm_mon,
		pTm->tm_mday,
		pTm->tm_hour,
		pTm->tm_min,
		pTm->tm_sec);

	strcpy(time_now, szTime);
}
int C3_is_equal(BYTE* cipher_C3, BYTE* local_C_3)
{
	for (int i = 0; i < HASH_BYTE_LENGTH; i++)
	{
		if (cipher_C3[i] != local_C_3[i])
			return 0;
	}
	return 1;
}
