#include"interface.h"

int main()
{
    //send
    string private_A;
    string private_B;
    string plaintext;
    
    //receive
    string time_signcrytion;
    string time_unsigncrytion;
	bool flag_replay_attack;
	bool flag_tamper_attack;
	string timestamp;
    int state = 0;

    while(1)
    {
        switch (state)
        {
        case 0:
            send_private_A(private_A);
            state = 1;
            break;
        case 1:
            send_plaintext(plaintext);
            state=2;
            break;
        case 2:
            send_private_B(private_B);
            state=3;
            break;
        case 3:
            re_A_signtime(&time_signcrytion);
            state = 4;
            break;
        case 4:
            send_signal_A();
            state = 5;
            break;
        case 5:
            re_B_unsigntime(&time_unsigncrytion);
            state = 6;
            break;
        default:
            break;
        }
        if (state==6)
            break;
    }
    return 0;
}
void send_private_A(string private_A)
{
    send_msg(private_A,AIP,SENDPORT);
}
void send_private_B(string private_B)
{
    send_msg(private_B,BIP,SENDPORT);
}
void send_plaintext(string plaintext)
{
    send_msg(plaintext,AIP,SENDPORT);
}

void re_A_signtime(string *time_signcrytion)
{
    recv_msg(time_signcrytion,LISTENPORT);
}
void re_B_unsigntime(string *time_unsigncrytion)
{
    recv_msg(time_unsigncrytion,LISTENPORT);
}

//signal A to send cipher
void send_signal_A()
{
    send_msg("send",AIP,SENDPORT);
}

