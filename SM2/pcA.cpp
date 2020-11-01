#include"pcA.h"

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

    sm2_ec_key* key_A = NULL;
    sm2_ec_key* key_B = NULL;
	ec_param* ecp;

	int state=0; // state flag
	char buff[MAXLINE];
	int revlength;
	string temp;

    int listenInfd,listenBfd,sendInfd,sendBfd,connfd;
    struct sockaddr_in sendaddr,listenaddr;

	key_B = (sm2_ec_key*)OPENSSL_malloc(sizeof(sm2_ec_key));

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
    
	while(1)
	{
		switch (state)
		{
		case 0: // receive private_A
			if((connfd=accept(listenInfd,(struct sockaddr *)NULL,NULL))==-1)
			{
				printf("accept private_A error\n");
				state = 10;
				break;
			}
			revlength = recv(connfd,buff,MAXLINE,0);
			buff[revlength] = '\0';
			private_A = buff;
			cout<< private_A << endl;
			state = 1;
			memset(buff,0,MAXLINE);
			close(connfd);
			break;
		case 1: // recieve plaintext
			if((connfd=accept(listenInfd,(struct sockaddr *)NULL,NULL))==-1)
			{
				printf("accept plaintext error\n");
				state = 10;
				break;
			}
			revlength = recv(connfd,buff,MAXLINE,0);
			buff[revlength] = '\0';
			plaintext = buff;
			cout<< plaintext <<endl;
			state = 2;
			memset(buff,0,MAXLINE);
			close(connfd);
			break;
		case 2: //generate public and send public_A
			//initial two send port
    		if((sendInfd = socket(AF_INET,SOCK_STREAM,0))==-1)
			{
				printf("create socket error\n");
				return;
			}
    
    		memset(&sendaddr,0,sizeof(sendaddr));
			sendaddr.sin_family=AF_INET;
			sendaddr.sin_port=htons(SENDINPORT);

    		if(inet_pton(AF_INET,INIP,&sendaddr.sin_addr)<=0)
			{
				printf("inet_pton error\n");
				return;
			}

			if(connect(sendInfd,(struct sockaddr*)&sendaddr,sizeof(sendaddr))<0)
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
			sendaddr.sin_port=htons(SENDBPORT);

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
			
			gen_pub_from_pri_A(private_A,&public_A_x,&public_A_y,key_A,ecp);
			if (send(sendBfd,public_A_x.c_str(),public_A_x.length(),0)<0)
			{
				printf("send public_A_x error\n");
				state = 10;
				break;
			}
			if (send(sendBfd,public_A_y.c_str(),public_A_y.length(),0)<0)
			{
				printf("send public_A_y error\n");
				state = 10;
				break;
			}
			state = 3;
			break;
		case 3: // receive public_B_x
			if((connfd=accept(listenBfd,(struct sockaddr *)NULL,NULL))==-1)
			{
				printf("accept public_B error\n");
				state = 10;
				break;
			}
			revlength = recv(connfd,buff,MAXLINE,0);
			buff[revlength] = '\0';
			public_B_x = buff;
			state = 3;
			memset(buff,0,MAXLINE);
			close(connfd);
			break;
		case 4://recieve public_B_y
			if((connfd=accept(listenBfd,(struct sockaddr *)NULL,NULL))==-1)
			{
				printf("accept public_B error\n");
				state = 10;
				break;
			}
			revlength = recv(connfd,buff,MAXLINE,0);
			buff[revlength] = '\0';
			public_B_y = buff;
			state = 4;
			memset(buff,0,MAXLINE);
			close(connfd);
			break;
		case 5: // signencryption and send time to Interface
			key_B->P = xy_ecpoint_new(ecp);
			BN_hex2bn(&key_B->P->x,public_B_x.c_str());
			BN_hex2bn(&key_B->P->y,public_B_y.c_str());
			signcryption(plaintext,&flag_signcryption,&ciphertext,&time_signcrytion,key_A,key_B,ecp);
			sprintf(buff,"%lf",time_signcrytion);
			temp = buff;
			if (send(sendInfd,temp.c_str(),temp.length(),0)<0)
			{
				printf("send time error\n");
				state = 10;
				break;
			}
			state = 6;
			break;
		case 6: //wait signal and send ciphertext
			if((connfd=accept(listenInfd,(struct sockaddr *)NULL,NULL))==-1)
			{
				printf("accept signal error\n");
				state = 10;
				break;
			}
			revlength = recv(connfd,buff,MAXLINE,0);
			buff[revlength] = '\0';
			close(connfd);
			if (send(sendBfd,ciphertext.c_str(),ciphertext.length(),0)<0)
			{
				printf("send ciphertext error\n");
				state = 10;
				break;
			}
			state = 10;
			break;
		case 10: //error
			break;
		default:
			break;
		}
		if (state==10)
			break;
	}

	sm2_ec_key_free(key_B);
	ec_param_free(ecp);
	sm2_ec_key_free(key_A);
	close(sendBfd);
	close(sendInfd);
	close(listenInfd);
	close(listenBfd);
	return;
}