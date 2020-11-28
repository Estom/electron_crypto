//interface main function
#include"interface.h"
int listenAfd,listenBfd;
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
	bool flag_replay = true;
	bool flag_tamper = false;

    
    //receive
	string public_A="";
	string public_B="";
	string ciphertext_A;
	string ciphertext_B;
	string replay_ciphertext="";
	string tamper_ciphertext="";
	string plaintext_B;
    string time_signcrytion;
    string time_unsigncrytion;
	bool flag_signcrytion;
    bool flag_unsigncrytion;
	bool flag_replay_attack;
	bool flag_tamper_attack;
	string timestamp;
    int state = 0;

	initial_server();
	gen_pub_from_pri_A(private_A,&public_A);
	gen_pub_from_pri_B(private_B,&public_B);
	gen_pub_from_pri_A(private_A,&public_A);

	signcryption(plaintext,&flag_signcrytion,&ciphertext_A,&time_signcrytion);

	tamper_attack("",&flag_tamper,&tamper_ciphertext);
	replay_attack("",&flag_replay,&replay_ciphertext);

	re_B_ciphertext(listenBfd,&ciphertext_B);
	
	unsigncryption(&flag_unsigncrytion,&plaintext_B,\
					&time_unsigncrytion,&flag_replay_attack,\
					&flag_tamper_attack,&timestamp);
	
	send_msg("6",AIP,SENDAPORT);
	send_msg("3",BIP,SENDBPORT);
	
	cout<< "public_A" << public_A << endl;
	cout << "public_B" << public_B << endl;
	cout << "tamper_ciphertext" << tamper_ciphertext << endl;
	cout << "replay_ciphertext" << replay_ciphertext << endl;
	cout <<"time_signcrytion"<< time_signcrytion << endl;
	cout << "flag_unsigncrytion" << flag_unsigncrytion << endl;
	cout << "flag_replay_attack" << flag_replay_attack << endl;
	cout <<"flag_tamper_attack"<< flag_tamper_attack << endl;
	cout <<"time_unsigncrytion"<< time_unsigncrytion << endl;
	cout << "time_stamp" << timestamp << endl;

	close(listenBfd);
	close(listenAfd);
    return;
}
void initial_server()
{
	//int sendAfd,sendBfd,listenfd,connfd;
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
	return;
}

void signcryption(string plaintext,bool *flag_signcrytion,string *ciphertext,string *time_signcrytion)
{
	*flag_signcrytion = false;
	send_plaintext("2"+plaintext);
	send_start_sign();
	re_A_ciphertext(listenAfd,ciphertext);
    re_A_signtime(listenAfd,time_signcrytion);
	if ((*time_signcrytion).length()!=0)
	{
		*flag_signcrytion = true;
	}
	return;
}

void unsigncryption( bool* flag_unsigncryption, string* plaintext,  \
    string* time_unsigncryption,bool* flag_replay_attack, bool* flag_tamper_attack,string *timestamp)
{
	send_start_unsign();
	re_B_plaintext(listenBfd,plaintext);
	re_B_timeFlag(listenBfd,time_unsigncryption,\
				flag_unsigncryption,\
				flag_replay_attack,\
				flag_tamper_attack,\
				timestamp);
	return;
}
void gen_pub_from_pri_A(string private_A,string *public_A)
{
	send_private_A("1" + private_A);
	string public_A_x,public_A_y;
	re_A_public(listenAfd,&public_A_x,&public_A_y);
	(*public_A).append(public_A_x);
	(*public_A).append(public_A_y);
	return;
}
void gen_pub_from_pri_B(string private_B,string *public_B)
{
	send_private_B("1"+private_B);
	string public_B_x,public_B_y;
	re_B_public(listenBfd,&public_B_x,&public_B_y);
	(*public_B).append(public_B_x);
	(*public_B).append(public_B_y);
	return;
}
void intercept_cipher(string ciphertext, bool *flag_intercept, string *intercepted_ciphertext){
	*flag_intercept = true;
    *intercepted_ciphertext = ciphertext;
    return;
}
void receive_B(string *ciphertext_B){
	re_B_ciphertext(listenBfd,ciphertext_B);
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
					bool *flag_tamper_attack,\
					string *time_stamp)
{
	string temp;
	int len;
    rev_unit(listenfd,&temp);
	len = temp.length();
	// cout<<"changdu:"<<len<<endl;
	*flag_unsigncrytion = string2bool(temp[len-22]);
	*flag_replay_attack = string2bool(temp[len-21]);
	*flag_tamper_attack = string2bool(temp[len-20]);
	*time_unsigncrytion = temp.substr(0,len-22);
	*time_stamp = temp.substr(len-19,19);
    return;
}
void send_signal_A(bool flag_replay,bool flag_tamper)
{	
	string signal = "3";
	if (flag_replay)
		signal = "5";
	if (flag_tamper)
		signal = "4";
	cout<<signal<<endl;
    send_msg(signal,AIP,SENDAPORT);
    return;
}
void send_gen_public_A()
{
	send_msg("gen_public",AIP,SENDAPORT);
	return;
}
void send_gen_public_B()
{
	send_msg("gen_public",BIP,SENDBPORT);
	return;
}
void re_A_public(int listenfd,string *public_A_x,string *public_A_y)
{
	rev_unit(listenfd,public_A_x);
	rev_unit(listenfd,public_A_y);
	return;
}
void re_B_public(int listenfd,string *public_B_x,string *public_B_y)
{
	rev_unit(listenfd,public_B_x);
	rev_unit(listenfd,public_B_y);
	return;
}
void send_start_sign()
{
	send_msg("start",AIP,SENDAPORT);
	return;
}
void send_start_unsign()
{
	send_msg("2",BIP,SENDBPORT);
}
void re_A_ciphertext(int listenfd,string *ciphertext)
{
	rev_unit(listenfd,ciphertext);
	return;
}
void re_B_ciphertext(int listenfd,string *ciphertext)
{
	rev_unit(listenfd,ciphertext);
	return;
}
void re_B_plaintext(int listenfd,string *plaintext)
{
	rev_unit(listenfd,plaintext);
	return;
}

bool string2bool(char flag)
{
	if (flag=='1')
		return true;
	return false;
}

void send_msg(string msg,char* ip_add,int port)
{
	int sockfd,n;
	struct sockaddr_in servaddr;

	if ((sockfd=socket(AF_INET,SOCK_STREAM,0))<0)
	{
		printf("create socket error\n");
		return;
	}

	memset(&servaddr,0,sizeof(servaddr));
	servaddr.sin_family=AF_INET;
	servaddr.sin_port=htons(port);
	if(inet_pton(AF_INET,ip_add,&servaddr.sin_addr)<=0)
	{
		printf("inet_pton error\n");
		return;
	}

	if(connect(sockfd,(struct sockaddr*)&servaddr,sizeof(servaddr))<0)
	{
		printf("connect error\n");
		return;
	}

	if (send(sockfd,msg.c_str(),msg.length(),0)<0)
	{
		printf("send error\n");
		return;
	}
	close(sockfd);
	return;
}	
void recv_msg(string *msg,int port)
{
	int listenfd,connfd;
	struct sockaddr_in servaddr;
	char buff[4096];
	int n;
	if((listenfd = socket(AF_INET,SOCK_STREAM,0))==-1)
	{
		printf("create socket error\n");
		return;
	}

		memset(&servaddr,0,sizeof(servaddr));
		servaddr.sin_family = AF_INET;
		servaddr.sin_addr.s_addr = INADDR_ANY;
		servaddr.sin_port = htons(port);

		if(bind(listenfd,(struct sockaddr*)&servaddr,sizeof(servaddr))==-1)
		{
			printf("bind socket error\n");
			return;
		}

		if(listen(listenfd,10)==-1)
		{
			printf("listen socket error\n");
			return;
		}

	printf("========waiting for clients request==========");

	while(1)
	{
		if((connfd=accept(listenfd,(struct sockaddr *)NULL,NULL))==-1)
		{
			printf("accept socket error\n");
			continue;
		}
		n = recv(connfd,buff,MAXLINE,0);
		buff[n]='\0';
		printf("recv msg :%s\n",buff);
		close(connfd);
		break;
	}
	close(listenfd);
	*msg = buff;
	return;
}
void send_unit(int sendfd,string msg)
{
	if (send(sendfd,msg.c_str(),msg.length(),0)<0)
	{
		printf("send msg error\n");
	}
	return;
}
void rev_unit(int listenfd,string *msg)
{
	char buff[MAXLINE];
	int connfd,len;
	if((connfd=accept(listenfd,(struct sockaddr *)NULL,NULL))==-1)
	{
		printf("accept msg error\n");
	}
	len = recv(connfd,buff,MAXLINE,0);
	buff[len]='\0';
	*msg = buff;
	return;
}
//密文篡改攻击函数,随机数
void tamper_attack(string intercepted_ciphertext, bool* flag_do_tamper,string *ciphertext)
{
	if (*flag_do_tamper==true)
	{
		send_signal_A(false,true);
		re_A_ciphertext(listenAfd,ciphertext);
		send_signal_A(false,flag_do_tamper);
	}
}
//消息重放攻击函数，延迟发送
void replay_attack(string intercepted_ciphertext, bool* flag_do_replay,string *ciphertext)
{
	if (*flag_do_replay==true)
	{
		send_signal_A(true,false);
		re_A_ciphertext(listenAfd,ciphertext);
		// cout<<*ciphertext<<endl;
		send_signal_A(flag_do_replay,false);
	}
}


