#include"part5.h"
#include<pthread.h>

#define SENDAPORT 6669
#define LISTENAPORT 6668
#define SENDINPORT 6670
#define LISTENINPORT 6671
#define AIP "127.0.0.1"
#define INIP "127.0.0.1"

//main function
void main_function();

void rev_privateB(int listenfd,string *private_B);
void send_publicB_A(string public_B_x,string public_B_y);
void rev_publicA_x(int listenfd,string *public_A_x);
void rev_publicA_y(int listenid,string *public_A_y);
void rev_ciphertext(int listenfd,string *ciphertext);
void send_timeFlag(double time_unsigncrytionbool,\
                bool flag_unsigncrytion,bool flag_replay_attack,bool flag_tamper_attack,string timestamp);

void rev_gen_public(int listenfd);
void send_publicB_IN(string public_B_x,string public_B_y);
void send_ciphertext(string ciphertext);
void rev_start_unsign(int listenfd);
void send_plaintext(string plaintext);


string bool2string(bool flag);

//
void *thread_IN(void *ptr);//interface
void *thread_A(void *ptr);//A