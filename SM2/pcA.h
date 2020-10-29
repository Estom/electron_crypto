#include"part5.h"

#define SENDPORT 6666
#define LISTENPORT 6667
#define BIP "127.0.0.1"

//main function
void re_private_A(string *private_A);
void re_plaintext(string *plaintext);

void send_public(string public_A);
void re_public_B(string *public_B);

void send_ciphertext(string ciphertext);
void send_timesign(double time_signcrytion);