#include"pcB.h"

int main()
{
    main_function();
    return 0;
}
void main_function()
{
    string private_B;
    string ciphertext;
    string plaintext;
    double time_unsigncrytion;
    string public_A_x;
    string public_A_y;
    string public_B_x;
    string public_B_y;
    bool flag_unsigncrytion;
    bool flag_replay_attack = false;
	bool flag_tamper_attack = false;
    string timestamp;

    sm2_ec_key* key_A = NULL;
    sm2_ec_key* key_B = NULL;
	ec_param* ecp2;

    int listenAfd,listenInfd,connfd;
    struct sockaddr_in listenaddr;

    key_B = (sm2_ec_key*)OPENSSL_malloc(sizeof(sm2_ec_key));

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

     if((listenInfd = socket(AF_INET,SOCK_STREAM,0))==-1)
	{
		printf("create socket error\n");
		return;
	}
    memset(&listenaddr,0,sizeof(listenaddr));
	listenaddr.sin_family = AF_INET;
	listenaddr.sin_addr.s_addr = INADDR_ANY;
	listenaddr.sin_port = htons(LISTENINPORT);

	if(bind(listenInfd,(struct sockaddr*)&listenaddr,sizeof(listenaddr))==-1)
	{
		printf("bind socket error\n");
		return;
	}

	if(listen(listenInfd,10)==-1)
	{
		printf("listen socket error\n");
		return;
	}


    rev_privateB(listenInfd,&private_B);
    cout <<private_B <<endl;
    rev_publicA_x(listenAfd,&public_A_x);
    rev_publicA_y(listenAfd,&public_A_y);
	gen_pub_from_pri_B(private_B,&public_B_x,&public_B_y,key_B,ecp2);
    send_publicB(public_B_x,public_B_y);
    rev_ciphertext(listenAfd,&ciphertext);

	cout<< "11111"<<endl;
	key_A = (sm2_ec_key*)OPENSSL_malloc(sizeof(sm2_ec_key));
	cout<< "22222"<<endl;
    key_A->P = xy_ecpoint_new(ecp2);
	cout<< "3333"<<endl;
	BN_hex2bn(&key_A->P->x,public_A_x.c_str());
	cout<< "4444"<<endl;
	BN_hex2bn(&key_A->P->y,public_A_y.c_str());
	cout<< "5555"<<endl;
    unsigncryption(ciphertext,&flag_unsigncrytion,&plaintext,key_B,key_A,\
                    ecp2,&time_unsigncrytion,&flag_replay_attack,\
                    &flag_tamper_attack,&timestamp);
    cout << plaintext <<endl;
    send_timeFlag(time_unsigncrytion,\
                    flag_unsigncrytion,flag_replay_attack,flag_tamper_attack);

    sm2_ec_key_free(key_B);
	ec_param_free(ecp2);
	sm2_ec_key_free(key_A);
	close(listenInfd);
	close(listenAfd);
    return;
}

void rev_privateB(int listenfd,string *private_B)
{
    rev_unit(listenfd,private_B);
    return;
}
void send_publicB(string public_B_x,string public_B_y)
{
    send_msg(public_B_x,AIP,SENDAPORT);
    send_msg(public_B_x,AIP,SENDAPORT);
    return;
}
void rev_publicA_x(int listenfd,string *public_A_x)
{
    rev_unit(listenfd,public_A_x);
    return;
}
void rev_publicA_y(int listenid,string *public_A_y)
{
    rev_unit(listenid,public_A_y);
    return;
}
void rev_ciphertext(int listenfd,string *ciphertext)
{
    rev_unit(listenfd,ciphertext);
    return;
}
void send_timeFlag(double time_unsigncrytion,\
                    bool flag_unsigncrytion,bool flag_replay_attack,bool flag_tamper_attack)
{
    string temp;
    char buff[100];
    sprintf(buff,"%lf",time_unsigncrytion);
    temp = buff;
    temp.append(bool2string(flag_unsigncrytion));
    temp.append(bool2string(flag_replay_attack));
    temp.append(bool2string(flag_tamper_attack));
    send_msg(temp,INIP,SENDINPORT);
    return;
}
string bool2string(bool flag)
{
    if(flag)
        return "1";
    return "0";
}