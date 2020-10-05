﻿/*************************************************************************
        > File Name: SM2.h
        > Author:NEWPLAN
        > E-mail:newplan001@163.com
        > Created Time: Thu Apr 13 23:55:50 2017
 ************************************************************************/
#ifndef SM2_H
#define SM2_H

#include "part5.h"
#include<string>
using namespace std;


#define POINT_BIT_LENGTH_IN 256
#define TYPE_IN TYPE_GFp
#define SM2_PARAM_IN sm2_param_recommand
#define DELAY_TIME 20000 //ms

void main_1();//带接口的签密和解签密函数
void charArray2hex(BYTE * C,int length,string *ciphertext);
//将字符数组转换成十六进制的数组，然后在转换成string数组
void hex2charArray(BYTE* C, string ciphertext);

void signcryption(string plaintext,bool *flag_signcrytion,string *ciphertext,double *time_signcrytion);//签密函数
void unsigncryption(string ciphertext, bool* flag_unsigncryption, string* plaintext, double* time_unsigncryption, \
    bool* flag_replay_attack, bool* flag_tamper_attack,string *timestamp);//解签密函数

//密文截获函数
void intercept_cipher(string ciphertext, bool* flag_intercept, string* intercepted_ciphertext);
//密文篡改攻击函数,随机数
void tamper_attack(string intercepted_ciphertext, bool* flag_do_tamper, string* ciphertext);
//消息重放攻击函数，延迟发送
void replay_attack(string intercepted_ciphertext, bool* flag_do_replay, string* ciphertext);

//由私钥生成公钥
void gen_pub_from_pri_A(string private_key_str,string *public_A);
void gen_pub_from_pri_B(string private_key_str,string *public_B);

#endif