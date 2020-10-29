#include"part5.h"

using namespace std;

#define SENDPORT 6666 
#define LISTENPORT 6667
#define AIP "127.0.0.1"
#define BIP "127.0.0.1"

//main interface function
// initial
void send_private_A(string private_A);
void send_private_B(string private_B);
void send_plaintext(string plaintext);


void re_A_signtime(string *time_signcrytion);
void re_B_unsigntime(string *time_unsigncrytion);

//signal A to send cipher
void send_signal_A();

