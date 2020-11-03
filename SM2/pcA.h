#include"part5.h"

#define SENDBPORT 6668
#define LISTENBPORT 6669
#define SENDINPORT 6667
#define LISTENINPORT 6666
#define BIP "127.0.0.1"
#define INIP "127.0.0.1"

//main function
void main_function();

void rev_privateA(int listenfd,string *private_A);
void rev_plaintext(int listenfd,string *plaintext);
void send_publicA_B(string public_A_x,string public_A_y);
void rev_public_B_x(int listenfd,string *public_B_x);
void rev_public_B_y(int listenfd,string *public_B_y);
void rev_signal(int listenfd);
void send_ciphertext_B(string ciphertext);
void send_signtime(double time_signcryption);

void send_ciphertext_IN(string ciphertext);
void rev_gen_public(int listenfd);
void send_publicA_IN(string public_A_x,string public_A_y);
void rev_start_sign(int listenfd);