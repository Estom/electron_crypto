#include"pcA.h"

int main()
{
    string private_A;
    string plaintext;
    string ciphertext;
    double time_signcrytion;
    string public_A;
    string public_B;

    sm2_ec_key* key_A = NULL;
    sm2_ec_key* key_B = NULL;

    int state = 0;
    while(1)
    {
        switch (state)
        {
        case 0:
            re_private_A(&private_A);
            state = 1;
            break;
        case 1:
            
        default:
            break;
        }
    }
    return 0;
}
void re_private_A(string *private_A)
{
    recv_msg(private_A,LISTENPORT);
    return;
}
void re_plaintext(string *plaintext)
{
    recv_msg(plaintext,LISTENPORT);
    return;
}

void send_public(string public_A)
{
    send_msg(public_A,BIP,SENDPORT);
    return;
}
void re_public_B(string *public_B)
{
    recv_msg(public_B,LISTENPORT);
    return;
}

void send_ciphertext(string ciphertext)
{
    send_msg(ciphertext,BIP,SENDPORT);
    return;
}
void send_timesign(double time_signcrytion)
{
    send_msg(to_string(time_signcrytion),BIP,SENDPORT);
    return;
}