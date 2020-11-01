#include"part5.h"

using namespace std;

#define SENDAPORT 6666 
#define SENDBPORT 6671
#define LISTENAPORT 6667
#define LISTENBPORT 6670
#define AIP "127.0.0.1"
#define BIP "127.0.0.1"

//main interface function
void main_function();
// initial
void send_private_A(int sendfd,string private_A);
void send_private_B(int sendfd,string private_B);
void send_plaintext(int sendfd,string plaintext);


void re_A_signtime(int listenfd,string *time_signcrytion);
void re_B_timeFlag(int listenfd,string *time_unsigncrytion,\
                    bool *flag_unsigncrytion,\
                    bool *flag_replay_attack,\
                    bool *flag_tamper_attack);

//signal A to send cipher
void send_signal_A(int sendfd);

bool string2bool(char flag);

