#include"part5.h"

#define SENDPORT 6666
#define LISTENPORT 6667
#define AIP "127.0.0.1"
#define INIP "127.0.0.1"

//main function
void main_function();

void rev_privateB(int listenfd,string *private_B);
void send_publicB(int sendfd,string public_B_x,string public_B_y);
void rev_ciphertext(int listenfd,string *ciphertext);
void send_unsigntime(int sendfd,string time_unsigncrytion);