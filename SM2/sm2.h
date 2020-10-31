/*************************************************************************
        > File Name: SM2.h
        > Author:NEWPLAN
        > E-mail:newplan001@163.com
        > Created Time: Thu Apr 13 23:55:50 2017
 ************************************************************************/
#ifndef SM2_H
#define SM2_H

#include "sm2_common.h"
#include "xy_ecpoint.h"
#include "sm2_ec_key.h"
#include "util.h"
#include "sm2_test_param.h"
#include<string>
#include<stdlib.h>
#include<string.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<unistd.h>
#include <stdio.h>
#include<iostream>
#include <ctime>
#include<cstdlib>
#include<vector>
#include<algorithm>
#include<sys/time.h>
using namespace std;


#define POINT_BIT_LENGTH_IN 256
#define TYPE_IN TYPE_GFp
#define SM2_PARAM_IN sm2_param_recommand
#define DELAY_TIME 20000 //ms
#define PLAIN_LEN 150//明文长度
#define MAXLINE 2000

void main_1();//带接口的签密和解签密函数
void charArray2hex(BYTE * C,int length,string *ciphertext);
//将字符数组转换成十六进制的数组，然后在转换成string数组
void hex2charArray(BYTE* C, string ciphertext);

void signcryption(string plaintext,bool *flag_signcrytion,string *ciphertext,double *time_signcrytion,\
    sm2_ec_key* key_A,sm2_ec_key* key_B,ec_param* ecp);//签密函数

void unsigncryption(string ciphertext, bool* flag_unsigncryption, string* plaintext,  \
    sm2_ec_key* key_B,sm2_ec_key* key_A,ec_param* ecp2,\
    double* time_unsigncryption,bool* flag_replay_attack, bool* flag_tamper_attack,string *timestamp);//解签密函数

//密文截获函数
void intercept_cipher(string ciphertext, bool* flag_intercept, string* intercepted_ciphertext);
//密文篡改攻击函数,随机数
void tamper_attack(string intercepted_ciphertext, bool* flag_do_tamper, string* ciphertext);
//消息重放攻击函数，延迟发送
void replay_attack(string intercepted_ciphertext, bool* flag_do_replay, string* ciphertext);

//由私钥生成公钥
void gen_pub_from_pri_A(string private_key_str,string *public_A_x,string *public_A_y,sm2_ec_key* key_A,ec_param *ecp);
void gen_pub_from_pri_B(string private_key_str,string *public_B_x,string *public_B_y,sm2_ec_key* key_B,ec_param *ecp2);

//socket communication
void send_msg(string msg,char* ip_add,int port);
void recv_msg(string *msg,int port);
void send_unit(int sendfd,string msg);
void rev_unit(int listenfd,string *msg);

#endif