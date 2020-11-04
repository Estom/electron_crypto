#include"pcA.h"

int main()
{
	main_function();
    return 0;
}
void main_function()
{
    string private_A="128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263";
    string plaintext="hello";
    string ciphertext;
	string attack_ciphertext;
    double time_signcrytion;
	bool flag_signcryption;
    string public_A_x; //ru guo shi xiangtong de changdu ,ze jinxingxiugai
	string public_A_y;
    string public_B_x;
	string public_B_y;
	string signal;
	bool flag_do_tamper;
	bool flag_do_replay;

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
	rev_gen_public(listenInfd);
	gen_pub_from_pri_A(private_A,&public_A_x,&public_A_y);
	cout <<"public_A" << public_A_x<< public_A_y << endl;
	send_publicA_B(public_A_x,public_A_y);
	send_publicA_IN(public_A_x,public_A_y);

	rev_public_B_x(listenBfd,&public_B_x);
	rev_public_B_y(listenBfd,&public_B_y);
	cout << "public_B" << public_B_x << public_B_y << endl;

	rev_plaintext(listenInfd,&plaintext);
	cout<< "plaintext" <<plaintext <<endl;
	rev_start_sign(listenInfd);

	key_B = sm2_ec_key_new(ecp);
	
	BN_hex2bn(&key_B->P->x,public_B_x.c_str());
	BN_hex2bn(&key_B->P->y,public_B_y.c_str());
	signcryption(plaintext,&flag_signcryption,&ciphertext,&time_signcrytion);
	send_ciphertext_IN(ciphertext);
	
	send_signtime(time_signcrytion);
	rev_signal(listenInfd,&signal);
	if (signal == "send_B")
	{
		send_ciphertext_B(ciphertext);
	}
	if (signal == "send_tamper")
	{
		flag_do_replay = true;
		tamper_attack(ciphertext,&flag_do_replay,&attack_ciphertext);
		send_ciphertext_IN(attack_ciphertext);
		rev_signal(listenInfd,&signal);
		send_ciphertext_B(attack_ciphertext);
	}
	cout << signal << endl;
	if(signal == "send_replay")
	{
		flag_do_tamper = true;
		replay_attack(ciphertext,&flag_do_tamper,&attack_ciphertext);
		send_ciphertext_IN(attack_ciphertext);
		rev_signal(listenInfd,&signal);
		send_ciphertext_B(attack_ciphertext);
	}
	cout<<"ciphertext" << ciphertext << endl;

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
void send_publicA_B(string public_A_x,string public_A_y)
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
void rev_signal(int listenfd,string *signal)
{
	rev_unit(listenfd,signal);
	return;
}
void send_ciphertext_B(string ciphertext)
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
void send_ciphertext_IN(string ciphertext)
{
	send_msg(ciphertext,INIP,SENDINPORT);
	return;
}
void rev_gen_public(int listenfd)
{
	string temp;
	rev_unit(listenfd,&temp);
	return;
}
void send_publicA_IN(string public_A_x,string public_A_y)
{
	send_msg(public_A_x,INIP,SENDINPORT);
	send_msg(public_A_y,INIP,SENDINPORT);
	return;
}
void rev_start_sign(int listenfd)
{
	string temp;
	rev_unit(listenfd,&temp);
	return;
}