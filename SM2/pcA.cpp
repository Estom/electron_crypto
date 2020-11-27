#include"pcA.h"
string private_A;
string plaintext;
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
int listenInfd,listenBfd;
struct sockaddr_in listenaddr;

int main()
{
	main_function();
    return 0;
}
void main_function()
{
	pthread_t inter,pcb;
	
	intial_listener();

	if (pthread_create(&inter,NULL,thread_IN,NULL)!=0)
    {
        printf("inter fail");
    }
    if (pthread_create(&pcb,NULL,thread_B,NULL)!=0)
    {
        printf("pca fail");
    }

    if (inter!=0){
        pthread_join(inter,NULL);
        printf("inter close\n");
    }
    if (pcb!=0){
        pthread_join(pcb,NULL);
        printf("pcb close\n");
    }

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
void intial_listener()
{
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
	return;
}

void *thread_IN(void *ptr)
{
	while(true){
		string temp;
		rev_unit(listenInfd,&temp);
		switch(temp[0])
		{
			case '1': //gen public
				private_A = temp.substr(1,temp.length()-1);
				gen_pub_from_pri_A(private_A,&public_A_x,&public_A_y);
				cout <<"public_A" << public_A_x<< public_A_y << endl;
				send_publicA_B("0" + public_A_x,public_A_y);
				send_publicA_IN(public_A_x,public_A_y);
				break;
			case '2': //sign
				plaintext = temp.substr(1,temp.length()-1);
				cout<< "plaintext" <<plaintext <<endl;
				rev_start_sign(listenInfd);

				key_B = sm2_ec_key_new(ecp);
		
				BN_hex2bn(&key_B->P->x,public_B_x.c_str());
				BN_hex2bn(&key_B->P->y,public_B_y.c_str());
				signcryption(plaintext,&flag_signcryption,&ciphertext,&time_signcrytion);
				send_ciphertext_IN(ciphertext);
				send_signtime(time_signcrytion);
				break;
			case '3': // send B
				ciphertext = "1" + ciphertext;
				send_ciphertext_B(ciphertext);
				break;
			case '4': // send tamper
				flag_do_replay = true;
				tamper_attack(ciphertext,&flag_do_replay,&attack_ciphertext);
				send_ciphertext_IN(attack_ciphertext);
				rev_signal(listenInfd,&signal);
				attack_ciphertext = "1" + attack_ciphertext;
				send_ciphertext_B(attack_ciphertext);
				break;
			case '5': // send replay
				flag_do_replay = true;
				replay_attack(ciphertext,&flag_do_tamper,&attack_ciphertext);
				send_ciphertext_IN(attack_ciphertext);
				rev_signal(listenInfd,&signal);
				attack_ciphertext = "1" + attack_ciphertext;
				send_ciphertext_B(attack_ciphertext);
				break;
			case '6':
				send_msg("3",BIP,SENDBPORT);
				return NULL;
			default:break;
		}
	}
	return NULL;
}
void *thread_B(void *ptr)
{
	while(true){
		string temp;
		rev_unit(listenBfd,&temp);
		switch(temp[0])
		{
			case '1':
				public_B_x = temp.substr(1,temp.length()-1);
				rev_public_B_y(listenBfd,&public_B_y);
				break;
			case '3':
				return NULL;
			default:break;
		}
	}
	return NULL;
}