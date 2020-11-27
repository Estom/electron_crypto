#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<string>
#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<unistd.h>
#include<iostream>

using namespace std;

#define SENDAPORT 6666 
#define SENDBPORT 6671
#define LISTENAPORT 6667
#define LISTENBPORT 6670
#define MAXLINE 2000
#define AIP "127.0.0.1"
#define BIP "127.0.0.1"

//main interface function
void main_function();
void initial_server();
void signcryption(string plaintext,bool *flag_signcrytion,string *ciphertext,string *time_signcrytion); //jie mian qianmi hanshu
void unsigncryption( bool* flag_unsigncryption, string* plaintext,  \
    string* time_unsigncryption,bool* flag_replay_attack, bool* flag_tamper_attack,string *timestamp);//解签密函数

void gen_pub_from_pri_A(string private_A,string *public_A);
void gen_pub_from_pri_B(string private_B,string *public_B);

//密文篡改攻击函数,随机数
void tamper_attack(string intercepted_ciphertext, bool* flag_do_tamper,string *ciphertext);
//消息重放攻击函数，延迟发送
void replay_attack(string intercepted_ciphertext, bool* flag_do_replay,string *ciphertext);
void intercept_cipher(string ciphertext, bool *flag_intercept, string *intercepted_ciphertext);
void receive_B(string *ciphertext_B);


// initial
void send_private_A(string private_A);
void send_private_B(string private_B);
void send_plaintext(string plaintext);
void send_gen_public_A();
void send_gen_public_B();
void re_A_public(int listenfd,string *public_A_x,string *public_A_y);
void re_B_public(int listenfd,string *public_B_x,string *public_B_y);
void send_start_sign();
void send_start_unsign();
void re_A_signtime(int listenfd,string *time_signcrytion);
void re_A_ciphertext(int listenfd,string *ciphertext);
void re_B_ciphertext(int listenfd,string *ciphertext);
void re_B_plaintext(int listenfd,string *plaintext);
void re_B_timeFlag(int listenfd,string *time_unsigncrytion,\
                    bool *flag_unsigncrytion,\
                    bool *flag_replay_attack,\
                    bool *flag_tamper_attack,
                    string *time_stamp);


//signal A to send cipher
void send_signal_A(bool flag_replay,bool flag_tamper);

bool string2bool(char flag);

//socket communication
void send_msg(string msg,char* ip_add,int port);
void recv_msg(string *msg,int port);
void send_unit(int sendfd,string msg);
void rev_unit(int listenfd,string *msg);
