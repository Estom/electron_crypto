//interface main function
#include"interface.h"
int main()
{
    main_function();
    return 0;
}
void main_function()
{
    //send
    string private_A="128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263";
    string private_B="1649AB77A00637BD5E2EFE283FBF353534AA7F7CB89463F208DDBC2920BB0DA0";
    string plaintext="hello";
    
    //receive
    string time_signcrytion;
    string time_unsigncrytion;
    bool flag_unsigncrytion;
	bool flag_replay_attack;
	bool flag_tamper_attack;
	string timestamp;
    int state = 0;

    //int sendAfd,sendBfd,listenfd,connfd;
	int listenAfd,listenBfd;
    struct sockaddr_in listenaddr;

    //initial listen port
    if((listenAfd = socket(AF_INET,SOCK_STREAM,0))==-1)
	{
		printf("create socket error\n");
		return;
	}
    memset(&listenaddr,0,sizeof(listenaddr));
	listenaddr.sin_family = AF_INET;
	listenaddr.sin_addr.s_addr = INADDR_ANY;
	listenaddr.sin_port = htons(LISTENAPORT);

	if(bind(listenAfd,(struct sockaddr*)&listenaddr,sizeof(listenaddr))==-1)
	{
		printf("bind socket error\n");
		return;
	}

	if(listen(listenAfd,10)==-1)
	{
		printf("listen socket error\n");
		return;
	}
	if((listenBfd = socket(AF_INET,SOCK_STREAM,0))==-1)
	{
		printf("create socket error\n");
		return;
	}
    memset(&listenaddr,0,sizeof(listenaddr));
	listenaddr.sin_family = AF_INET;
	listenaddr.sin_addr.s_addr = INADDR_ANY;
	listenaddr.sin_port = htons(LISTENBPORT);

	if(bind(listenBfd,(struct sockaddr*)&listenaddr,sizeof(listenaddr))==-1)
	{
		printf("bind socket error\n");
		return;
	}

	if(listen(listenBfd,10)==-1)
	{
		printf("listen socket error\n");
		return;
	}

    send_private_A(private_A);
    send_private_B(private_B);
	getchar();
	send_plaintext(plaintext);
    re_A_signtime(listenAfd,&time_signcrytion);           
    send_signal_A();
    re_B_timeFlag(listenBfd,&time_unsigncrytion,\
				&flag_unsigncrytion,\
				&flag_replay_attack,\
				&flag_tamper_attack);
	cout << time_signcrytion << endl;
	cout << flag_unsigncrytion << endl;
	cout << flag_replay_attack << endl;
	cout << flag_tamper_attack << endl;
	cout << time_unsigncrytion << endl;

	close(listenBfd);
	close(listenAfd);
    return;
}
void send_private_A(string private_A)
{
    send_msg(private_A,AIP,SENDAPORT);
    return;
}
void send_private_B(string private_B)
{
    send_msg(private_B,BIP,SENDBPORT);
    return;
}
void send_plaintext(string plaintext)
{
    send_msg(plaintext,AIP,SENDAPORT);
    return;
}
void re_A_signtime(int listenfd,string *time_signcrytion)
{
    rev_unit(listenfd,time_signcrytion);
    return;
}
void re_B_timeFlag(int listenfd,string *time_unsigncrytion,\
                    bool *flag_unsigncrytion,\
					bool *flag_replay_attack,\
					bool *flag_tamper_attack)
{
	string temp;
	int len;
    rev_unit(listenfd,&temp);
	len = temp.length();
	*flag_unsigncrytion = string2bool(temp[len-3]);
	*flag_replay_attack = string2bool(temp[len-2]);
	*flag_tamper_attack = string2bool(temp[len-1]);
	*time_unsigncrytion = temp.substr(0,len-3);
    return;
}
void send_signal_A()
{
    string signal = "send";
    send_msg(signal,AIP,SENDAPORT);
    return;
}
bool string2bool(char flag)
{
	if (flag=='1')
		return true;
	return false;
}

