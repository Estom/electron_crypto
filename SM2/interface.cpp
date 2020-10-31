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

    int sendAfd,sendBfd,listenfd,connfd;
    struct sockaddr_in sendaddr,listenaddr;

    //initial listen port
    if((listenfd = socket(AF_INET,SOCK_STREAM,0))==-1)
	{
		printf("create socket error\n");
		return;
	}
    memset(&listenaddr,0,sizeof(listenaddr));
	listenaddr.sin_family = AF_INET;
	listenaddr.sin_addr.s_addr = INADDR_ANY;
	listenaddr.sin_port = htons(LISTENPORT);

	if(bind(listenfd,(struct sockaddr*)&listenaddr,sizeof(listenaddr))==-1)
	{
		printf("bind socket error\n");
		return;
	}

	if(listen(listenfd,10)==-1)
	{
		printf("listen socket error\n");
		return;
	}

    //initial two send port
    if((sendAfd = socket(AF_INET,SOCK_STREAM,0))==-1)
	{
		printf("create socket error\n");
		return;
	}
    
    memset(&sendaddr,0,sizeof(sendaddr));
	sendaddr.sin_family=AF_INET;
	sendaddr.sin_port=htons(SENDPORT);

    if(inet_pton(AF_INET,AIP,&sendaddr.sin_addr)<=0)
	{
		printf("inet_pton error\n");
		return;
	}

	if(connect(sendAfd,(struct sockaddr*)&sendaddr,sizeof(sendaddr))<0)
	{
		printf("connect Interface error\n");
		return;
	}

    if((sendBfd = socket(AF_INET,SOCK_STREAM,0))==-1)
	{
		printf("create socket error\n");
		return;
	}
    
    memset(&sendaddr,0,sizeof(sendaddr));
	sendaddr.sin_family=AF_INET;
	sendaddr.sin_port=htons(SENDPORT);

    if(inet_pton(AF_INET,BIP,&sendaddr.sin_addr)<=0)
	{
		printf("inet_pton error\n");
		return;
	}

	if(connect(sendBfd,(struct sockaddr*)&sendaddr,sizeof(sendaddr))<0)
	{
		printf("connect B error\n");
		return;
	}

    while(1)
    {
        switch (state)
        {
        case 0:
            send_private_A(sendAfd,private_A);
            state = 1;
            break;
        case 1:
            send_plaintext(sendAfd,plaintext);
            state=2;
            break;
        case 2:
            send_private_B(sendBfd,private_B);
            state=3;
            break;
        case 3:
            re_A_signtime(listenfd,&time_signcrytion);
            state = 4;
            break;
        case 4:
            send_signal_A(sendAfd);
            state = 5;
            break;
        case 5:
            re_B_unsigntime(listenfd,&time_unsigncrytion);
            state = 6;
            break;
        default:
            break;
        }
        if (state==6)
            break;
    }
    return;
}
void send_private_A(int sendfd,string private_A)
{
    send_unit(sendfd,private_A);
    return;
}
void send_private_B(int sendfd,string private_B)
{
    send_unit(sendfd,private_B);
    return;
}
void send_plaintext(int sendfd,string plaintext)
{
    send_unit(sendfd,plaintext);
    return;
}
void re_A_signtime(int listenfd,string *time_signcrytion)
{
    rev_unit(listenfd,time_signcrytion);
    return;
}
void re_B_unsigntime(int listenfd,string *time_unsigncrytion)
{
    rev_unit(listenfd,time_unsigncrytion);
    return;
}
void send_signal_A(int sendfd)
{
    string signal = "send";
    send_unit(sendfd,signal);
    return;
}

