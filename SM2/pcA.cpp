#include"pcA.h"

sm2_ec_key* key_A = NULL;
sm2_ec_key* key_B = NULL;
BIGNUM *b_x = BN_new();
BIGNUM *b_y = BN_new();
ec_param* ecp;

int main()
{
	main_function();
    return 0;
}
void main_function()
{
    string private_A;
    string plaintext;
    string ciphertext;
    double time_signcrytion;
	bool flag_signcryption;
    string public_A_x; //ru guo shi xiangtong de changdu ,ze jinxingxiugai
	string public_A_y;
    string public_B_x;
	string public_B_y;

	int state=0; // state flag
	char buff[MAXLINE];
	int revlength;
	string temp;

    int listenInfd,listenBfd;
    struct sockaddr_in listenaddr;

    //initial listen port
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
    
	rev_privateA(listenInfd,&private_A);
	cout<< private_A << endl;
	rev_plaintext(listenInfd,&plaintext);
	cout<< plaintext <<endl;
			
	gen_pub_from_pri_A(private_A,&public_A_x,&public_A_y,key_A,ecp);
	send_publicA(public_A_x,public_A_y);
	rev_public_B_x(listenBfd,&public_B_x);
	rev_public_B_y(listenBfd,&public_B_y);

	/*cout << "1"<<endl;
	key_B = (sm2_ec_key*)OPENSSL_malloc(sizeof(sm2_ec_key));
	key_B = sm2_ec_key_new(ecp);
	cout << "2"<<endl;
	key_B->P = xy_ecpoint_new(ecp);
	cout << "3"<<endl;*/
	BN_hex2bn(&b_x,public_B_x.c_str());
	BN_hex2bn(&b_y,public_B_y.c_str());
	signcryption(plaintext,&flag_signcryption,&ciphertext,&time_signcrytion,key_A,b_x,b_y,ecp);
	
	send_signtime(time_signcrytion);
	rev_signal(listenInfd);
	send_ciphertext(ciphertext);

	sm2_ec_key_free(key_B);
	ec_param_free(ecp);
	sm2_ec_key_free(key_A);
	close(listenInfd);
	close(listenBfd);
	return;
}

void rev_privateA(int listenfd,string *private_A)
{
	rev_unit(listenfd,private_A);
	return;
}
void rev_plaintext(int listenfd,string *plaintext)
{
	rev_unit(listenfd,plaintext);
	return;
}
void send_publicA(string public_A_x,string public_A_y)
{
	send_msg(public_A_x,BIP,SENDBPORT);
	send_msg(public_A_y,BIP,SENDBPORT);
	return;
}
void rev_public_B_x(int listenfd,string *public_B_x)
{
	rev_unit(listenfd,public_B_x);
	return;
}
void rev_public_B_y(int listenfd,string *public_B_y)
{
	rev_unit(listenfd,public_B_y);
	return;
}
void rev_signal(int listenfd)
{
	string temp;
	rev_unit(listenfd,&temp);
	return;
}
void send_ciphertext(string ciphertext)
{
	send_msg(ciphertext,BIP,SENDBPORT);
	return;
}
void send_signtime(double time_signcryption)
{
	char buff[100];
	sprintf(buff,"%lf",time_signcryption);
	string temp = buff;
	send_msg(temp,INIP,SENDINPORT);
	return;
}