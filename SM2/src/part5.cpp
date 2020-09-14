/*************************************************************************
        > File Name: part4.c
        > Author:NEWPLAN
        > E-mail:newplan001@163.com
        > Created Time: Thu Apr 13 23:55:50 2017
 ************************************************************************/
// sign-verify
#include "part2.h"
#include "sm2_ec_key.h"

// encrypt-decrypt
#include "part4.h"
#include "part5.h"

const int PRINT_MESSAGE = 0;
#define TIMES 1000

typedef struct
{
	BYTE *message;
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
	BYTE *message;
	int message_byte_length;
	BYTE *ID;
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

/*sm2加密信息*/
int sm2_encrypt_copy(ec_param *ecp, message_st *message_data)
{
	BIGNUM *P_x;
	BIGNUM *P_y;
	//BIGNUM *d;
	BIGNUM *k;
	xy_ecpoint *P;
	xy_ecpoint *xy1;
	xy_ecpoint *xy2;
	int pos1;
	BYTE *t;
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

	xy_ecpoint_init_xy(P, P_x, P_y, ecp);
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

	t = KDF((BYTE *)message_data->C_2, message_data->klen_bit, ecp->point_byte_length + ecp->point_byte_length);
	for (i = 0; i < message_data->message_byte_length; i++)
	{
		message_data->C_2[i] = t[i] ^ message_data->message[i];
	}
	OPENSSL_free(t);

	//计算C_3
	memset(&local_C_3, 0, sizeof(local_C_3));
	BUFFER_APPEND_BIGNUM(local_C_3.buffer, local_C_3.position, ecp->point_byte_length, xy2->x);
	BUFFER_APPEND_STRING(local_C_3.buffer, local_C_3.position, message_data->message_byte_length, message_data->message);
	BUFFER_APPEND_BIGNUM(local_C_3.buffer, local_C_3.position, ecp->point_byte_length, xy2->y);
	SM3_Init();
	SM3_Update((BYTE *)local_C_3.buffer, local_C_3.position);
	SM3_Final_byte(local_C_3.hash);
	memcpy(message_data->C_3, (char *)local_C_3.hash, HASH_BYTE_LENGTH);

	pos1 = 0;
	BUFFER_APPEND_STRING(message_data->C, pos1, 1 + ecp->point_byte_length + ecp->point_byte_length, message_data->C_1);
	BUFFER_APPEND_STRING(message_data->C, pos1, message_data->message_byte_length, message_data->C_2);
	BUFFER_APPEND_STRING(message_data->C, pos1, HASH_BYTE_LENGTH, message_data->C_3);

	
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

	return SUCCESS;
}

int sm2_decrypt_copy(ec_param *ecp, message_st *message_data)
{
	int pos1;
	int pos2;
	xy_ecpoint *xy1;
	xy_ecpoint *xy2;
	BIGNUM *d;
	BYTE KDF_buffer[MAX_POINT_BYTE_LENGTH * 2];
	BYTE *t;
	int i;

	xy1 = xy_ecpoint_new(ecp);
	xy2 = xy_ecpoint_new(ecp);
	d = BN_new();

	pos1 = 0;
	pos2 = 0;
	BUFFER_APPEND_STRING(message_data->C_1, pos1, 1 + ecp->point_byte_length + ecp->point_byte_length, &message_data->C[pos2]);
	pos2 = pos2 + pos1;
	pos1 = 0;
	BUFFER_APPEND_STRING(message_data->C_2, pos1, message_data->message_byte_length, &message_data->C[pos2]);
	pos2 = pos2 + pos1;
	pos1 = 0;
	BUFFER_APPEND_STRING(message_data->C_3, pos1, HASH_BYTE_LENGTH, &message_data->C[pos2]);
	pos2 = pos2 + pos1;

	BN_bin2bn(&message_data->C_1[1], ecp->point_byte_length, xy1->x);
	BN_bin2bn(&message_data->C_1[1 + ecp->point_byte_length], ecp->point_byte_length, xy1->y);

	BN_bin2bn(message_data->private_key, ecp->point_byte_length, d);
	xy_ecpoint_init_xy(xy1, xy1->x, xy1->y, ecp);
	xy_ecpoint_mul_bignum(xy2, xy1, d, ecp);

	pos1 = 0;
	memset(KDF_buffer, 0, sizeof(KDF_buffer));
	BUFFER_APPEND_BIGNUM(KDF_buffer, pos1, ecp->point_byte_length, xy2->x);
	BUFFER_APPEND_BIGNUM(KDF_buffer, pos1, ecp->point_byte_length, xy2->y);
	if (PRINT_MESSAGE) {
		DEFINE_SHOW_BIGNUM(d);
		DEFINE_SHOW_BIGNUM(xy2->x);
		DEFINE_SHOW_BIGNUM(xy2->y);
	}
	t = KDF((BYTE *)KDF_buffer, message_data->klen_bit, ecp->point_byte_length + ecp->point_byte_length);

	for (i = 0; i < message_data->message_byte_length; i++)
	{
		message_data->decrypt[i] = t[i] ^ message_data->C_2[i];
	}
	OPENSSL_free(t);

	xy_ecpoint_free(xy1);
	xy_ecpoint_free(xy2);
	BN_free(d);

	return SUCCESS;
}

void sm2_sign_modified(ec_param *ecp, sm2_sign_st *sign, message_st *message_data)
{
	sm2_hash Z_A;
	sm2_hash e;
	BIGNUM *e_bn;

	BIGNUM *r;
	BIGNUM *s;
	BIGNUM *tmp1;

	BIGNUM *P_x;
	BIGNUM *P_y;
	BIGNUM *d;
	BIGNUM *k;
	xy_ecpoint *xy1;

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
	
	/*
	// old
	memset(&Z_A, 0, sizeof(Z_A));
	Z_A.buffer[0] = ((sign->ENTL * 8) >> 8) & 0xFF;
	Z_A.buffer[1] = (sign->ENTL * 8) & 0xFF;
	Z_A.position = Z_A.position + 2;
	BUFFER_APPEND_STRING(Z_A.buffer, Z_A.position, sign->ENTL, sign->ID);
	BUFFER_APPEND_BIGNUM(Z_A.buffer, Z_A.position, ecp->point_byte_length, ecp->a);
	BUFFER_APPEND_BIGNUM(Z_A.buffer, Z_A.position, ecp->point_byte_length, ecp->b);
	BUFFER_APPEND_BIGNUM(Z_A.buffer, Z_A.position, ecp->point_byte_length, ecp->G->x);
	BUFFER_APPEND_BIGNUM(Z_A.buffer, Z_A.position, ecp->point_byte_length, ecp->G->y);
	BUFFER_APPEND_BIGNUM(Z_A.buffer, Z_A.position, ecp->point_byte_length, P_x);
	BUFFER_APPEND_BIGNUM(Z_A.buffer, Z_A.position, ecp->point_byte_length, P_y);
	DEFINE_SHOW_STRING(Z_A.buffer, Z_A.position);
	SM3_Init();
	SM3_Update(Z_A.buffer, Z_A.position);
	SM3_Final_byte(Z_A.hash);
	memcpy(sign->Z, Z_A.hash, HASH_BYTE_LENGTH);

	DEFINE_SHOW_STRING(Z_A.hash, HASH_BYTE_LENGTH);

	memset(&e, 0, sizeof(e));
	BUFFER_APPEND_STRING(e.buffer, e.position, HASH_BYTE_LENGTH, Z_A.hash);
	BUFFER_APPEND_STRING(e.buffer, e.position, strlen(message_digest), (BYTE *)message_digest);
	SM3_Init();
	SM3_Update(e.buffer, e.position);
	SM3_Final_byte(e.hash);
	DEFINE_SHOW_STRING(e.hash, HASH_BYTE_LENGTH);
	DEFINE_SHOW_STRING(sign->k, ecp->point_byte_length);

	BN_bin2bn(e.hash, HASH_BYTE_LENGTH, e_bn);
	*/
	// new
	BN_bin2bn(message_data->C_2, message_data->message_byte_length, e_bn);

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

void sm2_verify_modified(ec_param *ecp, sm2_sign_st *sign, message_st *message_data)
{
	sm2_hash e;
	BIGNUM *e_bn;
	BIGNUM *t;
	BIGNUM *R;
	xy_ecpoint *result;
	xy_ecpoint *result1;
	xy_ecpoint *result2;
	xy_ecpoint *P_A;
	BIGNUM *r;
	BIGNUM *s;
	BIGNUM *P_x;
	BIGNUM *P_y;

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
	
	/*
	// old
	memset(&e, 0, sizeof(e));
	BUFFER_APPEND_STRING(e.buffer, e.position, HASH_BYTE_LENGTH, sign->Z);
	BUFFER_APPEND_STRING(e.buffer, e.position, sign->message_byte_length, (BYTE *)sign->message);
	SM3_Init();
	SM3_Update(e.buffer, e.position);
	SM3_Final_byte(e.hash);
	BN_bin2bn(e.hash, HASH_BYTE_LENGTH, e_bn);
	*/
	// new
	BN_bin2bn(message_data->C_2, message_data->message_byte_length, e_bn);
	
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

void test_part5(char **sm2_param, int type, int point_bit_length)
{	
	/* enc-dec init begin */
	ec_param *ecp;
	sm2_ec_key *key_B;
	message_st message_data;

	ecp = ec_param_new();
	ec_param_init(ecp, sm2_param, type, point_bit_length);

	key_B = sm2_ec_key_new(ecp);
	sm2_ec_key_init(key_B, sm2_param_d_B[ecp->type], ecp);

	memset(&message_data, 0, sizeof(message_data));
	message_data.message = (BYTE *)message;
	message_data.message_byte_length = strlen((char *)message_data.message);
	
	//
	static int count = 0;
	if (!count)
		printf("raw message length: %dB\n", message_data.message_byte_length);

	message_data.klen_bit = message_data.message_byte_length * 8;
	sm2_hex2bin((BYTE *)sm2_param_k[ecp->type], message_data.k, ecp->point_byte_length);
	sm2_bn2bin(key_B->d, message_data.private_key, ecp->point_byte_length);
	sm2_bn2bin(key_B->P->x, message_data.public_key.x, ecp->point_byte_length);
	sm2_bn2bin(key_B->P->y, message_data.public_key.y, ecp->point_byte_length);
	if (PRINT_MESSAGE) {
		DEFINE_SHOW_BIGNUM(key_B->d);
		DEFINE_SHOW_BIGNUM(key_B->P->x);
		DEFINE_SHOW_BIGNUM(key_B->P->y);
	}

	message_data.decrypt = (BYTE *)OPENSSL_malloc(message_data.message_byte_length + 1);
	memset(message_data.decrypt, 0, message_data.message_byte_length + 1);
	/* enc-dec init end*/ 



	sm2_encrypt_copy(ecp, &message_data);

	//
	if (!count) {
		printf("after encryption: %dB\n", strlen((char *)message_data.C));
		// count += 1;
	}


	/* sig-ver init begin */
	ec_param *ecp2;
	sm2_ec_key *key_A;
	sm2_sign_st sign;

	ecp2 = ec_param_new();
	ec_param_init(ecp2, sm2_param, type, point_bit_length);

	key_A = sm2_ec_key_new(ecp2);
	sm2_ec_key_init(key_A, sm2_param_digest_d_A[ecp2->type], ecp2);

	memset(&sign, 0, sizeof(sign));
	// old	
	// sign.message = (BYTE *)message_digest;
	// sign.message_byte_length = strlen(message_digest);
	// new
	sign.message = (BYTE *)message_data.C;
	sign.message_byte_length = strlen((char *)message_data.C);
	sign.ID = (BYTE *)ID_A;
	sign.ENTL = strlen(ID_A);
	sm2_hex2bin((BYTE *)sm2_param_digest_k[ecp2->type], sign.k, ecp2->point_byte_length);
	sm2_bn2bin(key_A->d, sign.private_key, ecp2->point_byte_length);
	sm2_bn2bin(key_A->P->x, sign.public_key.x, ecp2->point_byte_length);
	sm2_bn2bin(key_A->P->y, sign.public_key.y, ecp2->point_byte_length);
	
	if (PRINT_MESSAGE) {
		DEFINE_SHOW_STRING(sign.public_key.x, ecp2->point_byte_length);
		DEFINE_SHOW_STRING(sign.public_key.y, ecp2->point_byte_length);
	}
	/* sig-ver init end */
	

	
	sm2_sign_modified(ecp2, &sign, &message_data);
	//
	if (!count) {
		printf("after encryption with r and s: %dB\n\n",
					   	strlen((char *)message_data.C) + strlen((char *)sign.s) + strlen((char *)sign. r));
		count += 1;
	}
	memset(sign.private_key, 0, sizeof(sign.private_key)); // 清除私钥
	sm2_verify_modified(ecp2, &sign, &message_data);
	sm2_decrypt_copy(ecp, &message_data);



	/**************************** free *****************************/
	/* enc-dec free begin */
	if (PRINT_MESSAGE)	
		printf("decrypt: len: %d\n%s\n", strlen((const char *)message_data.decrypt), message_data.decrypt);
	OPENSSL_free(message_data.decrypt);

	sm2_ec_key_free(key_B);
	ec_param_free(ecp);
	/* enc-dec free end */


	/* sig-ver free begin */
	sm2_ec_key_free(key_A);
	ec_param_free(ecp2);
	/* sig-ver free end */
}

message_st message_data_array[TIMES];
sm2_sign_st sign_array[TIMES];
ec_param *ecp_array[TIMES];
ec_param *ecp2_array[TIMES];
void test_part5_enc_sig(char **sm2_param, int type, int point_bit_length)
{	
	static int i = 0;
	/* enc-dec init begin */
	// ec_param *ecp;
	sm2_ec_key *key_B;	
	// message_st message_data;

	ecp_array[i] = ec_param_new();
	ec_param_init(ecp_array[i], sm2_param, type, point_bit_length);

	key_B = sm2_ec_key_new(ecp_array[i]);
	sm2_ec_key_init(key_B, sm2_param_d_B[ecp_array[i]->type], ecp_array[i]);

	memset(&message_data_array[i], 0, sizeof(message_data_array[i]));
	message_data_array[i].message = (BYTE *)message;
	message_data_array[i].message_byte_length = strlen((char *)message_data_array[i].message);
	message_data_array[i].klen_bit = message_data_array[i].message_byte_length * 8;
	sm2_hex2bin((BYTE *)sm2_param_k[ecp_array[i]->type], message_data_array[i].k, ecp_array[i]->point_byte_length);
	sm2_bn2bin(key_B->d, message_data_array[i].private_key, ecp_array[i]->point_byte_length);
	sm2_bn2bin(key_B->P->x, message_data_array[i].public_key.x, ecp_array[i]->point_byte_length);
	sm2_bn2bin(key_B->P->y, message_data_array[i].public_key.y, ecp_array[i]->point_byte_length);
	if (PRINT_MESSAGE) {
		DEFINE_SHOW_BIGNUM(key_B->d);
		DEFINE_SHOW_BIGNUM(key_B->P->x);
		DEFINE_SHOW_BIGNUM(key_B->P->y);
	}

	message_data_array[i].decrypt = (BYTE *)OPENSSL_malloc(message_data_array[i].message_byte_length + 1);
	memset(message_data_array[i].decrypt, 0, message_data_array[i].message_byte_length + 1);
	/* enc-dec init end*/ 



	sm2_encrypt_copy(ecp_array[i], &message_data_array[i]);



	/* sig-ver init begin */
	// ec_param *ecp2;
	sm2_ec_key *key_A;
	// sm2_sign_st sign;

	ecp2_array[i] = ec_param_new();
	ec_param_init(ecp2_array[i], sm2_param, type, point_bit_length);

	key_A = sm2_ec_key_new(ecp2_array[i]);
	sm2_ec_key_init(key_A, sm2_param_digest_d_A[ecp2_array[i]->type], ecp2_array[i]);

	memset(&sign_array[i], 0, sizeof(sign_array[i]));
	// old	
	// sign.message = (BYTE *)message_digest;
	// sign.message_byte_length = strlen(message_digest);
	// new
	sign_array[i].message = (BYTE *)message_data_array[i].C;
	sign_array[i].message_byte_length = strlen((char *)message_data_array[i].C);
	sign_array[i].ID = (BYTE *)ID_A;
	sign_array[i].ENTL = strlen(ID_A);
	sm2_hex2bin((BYTE *)sm2_param_digest_k[ecp2_array[i]->type], sign_array[i].k, ecp2_array[i]->point_byte_length);
	sm2_bn2bin(key_A->d, sign_array[i].private_key, ecp2_array[i]->point_byte_length);
	sm2_bn2bin(key_A->P->x, sign_array[i].public_key.x, ecp2_array[i]->point_byte_length);
	sm2_bn2bin(key_A->P->y, sign_array[i].public_key.y, ecp2_array[i]->point_byte_length);
	
	if (PRINT_MESSAGE) {
		DEFINE_SHOW_STRING(sign_array[i].public_key.x, ecp2_array[i]->point_byte_length);
		DEFINE_SHOW_STRING(sign_array[i].public_key.y, ecp2_array[i]->point_byte_length);
	}
	/* sig-ver init end */
	

	
	sm2_sign_modified(ecp2_array[i], &sign_array[i], &message_data_array[i]);


	/**************************** free *****************************/
	/* enc-dec free begin */
	if (PRINT_MESSAGE)	
		printf("decrypt: len: %d\n%s\n", strlen((const char *)message_data_array[i].decrypt), message_data_array[i].decrypt);

	sm2_ec_key_free(key_B);
	// ec_param_free(ecp_array[i]);
	/* enc-dec free end */


	/* sig-ver free begin */
	sm2_ec_key_free(key_A);
	// ec_param_free(ecp2_array[i]);
	/* sig-ver free end */
	i++;
}

void test_part5_ver_dec(char **sm2_param, int type, int point_bit_length)
{	
	static int i = 0;
	memset(sign_array[i].private_key, 0, sizeof(sign_array[i].private_key)); // 清除私钥
	sm2_verify_modified(ecp2_array[i], &sign_array[i], &message_data_array[i]);
	sm2_decrypt_copy(ecp_array[i], &message_data_array[i]);


	/**************************** free *****************************/
	/* enc-dec free begin */
	if (PRINT_MESSAGE)	
		printf("decrypt: len: %d\n%s\n", strlen((const char *)message_data_array[i].decrypt), message_data_array[i].decrypt);
	OPENSSL_free(message_data_array[i].decrypt);

	/* enc-dec free begin */
	ec_param_free(ecp_array[i]);
	/* enc-dec free end */


	/* sig-ver free begin */
	ec_param_free(ecp2_array[i]);
	/* sig-ver free end */
	i++;
}
