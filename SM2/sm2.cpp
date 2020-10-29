/*************************************************************************
		> File Name: SM2.c
		> Author:NEWPLAN
		> E-mail:newplan001@163.com
		> Created Time: Thu Apr 13 23:55:50 2017
 ************************************************************************/
#pragma comment(lib,"libssl.lib")
#pragma comment(lib,"libcrypto.lib")
#include "part5.h"

int main()
{
	main_1();
	return 0;
}

//随机产生明文
void gen_plaintext(int length, string* plaintext)
{
	srand((int)time(NULL));
	char temp[MES_LEN] = { '\0' };
	for (int i = 0; i < length; i++)
	{
		temp[i] = (rand() % 26) + 'a';
	}
	*plaintext = temp;
	return;
}

void main_1()
{
	string private_A= "128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263";
	string private_B= "1649AB77A00637BD5E2EFE283FBF353534AA7F7CB89463F208DDBC2920BB0DA0";
	string public_A;
	string public_B;

	string plaintext;
	bool flag_signcrytion;
	string ciphertext;
	double time_signcrytion;
	bool flag_unsigncrytion;
	string de_plaintext;
	double time_unsigncrytion;
	bool flag_replay_attack;
	bool flag_tamper_attack;
	string timestamp;

	//攻击的一些参数
	string intercepted_ciphertext;
	bool flag_intercept = true;
	bool flag_do_tamper = true;
	bool flag_do_replay = true;
	string ciphertext_attack;

	//随机产生明文
	gen_plaintext(PLAIN_LEN, &plaintext);

	//初始化密钥
	gen_pub_from_pri_A(private_A,&public_A);
	gen_pub_from_pri_B(private_B,&public_B);

	//显示明文，十六进制
	//string plaintext_hex;
	//charArray2hex((BYTE*)plaintext.c_str(), plaintext.length(), &plaintext_hex);
	//cout << "明文: " << plaintext_hex << endl << endl;

	
	//正常加解密
	signcryption(plaintext, &flag_signcrytion, &ciphertext, &time_signcrytion);
	unsigncryption(ciphertext, &flag_unsigncrytion, &de_plaintext, \
		&time_unsigncrytion, &flag_replay_attack, &flag_tamper_attack, &timestamp);
	//cout << ciphertext << endl;
	printf("加密时间:%lfus\n", time_signcrytion);
	printf("解密时间:%lfus\n", time_unsigncrytion);
	//cout << "密文: " << ciphertext << endl << endl;
	//显示解密后的明文，十六进制
	//string de_plaintext_hex;
	//charArray2hex((BYTE*)de_plaintext.c_str(), de_plaintext.length(), &de_plaintext_hex);
	//cout << "解密后明文: " << de_plaintext_hex << endl << endl;
	//cout << timestamp << endl;//输出时间戳
	

	/*
	//篡改攻击
	printf("篡改攻击\n");
	signcryption(plaintext, &flag_signcrytion, &ciphertext, &time_signcrytion);
	cout << "密文: " << ciphertext << endl << endl;
	intercept_cipher(ciphertext, &flag_intercept, &intercepted_ciphertext);
	tamper_attack(intercepted_ciphertext, &flag_do_tamper, &ciphertext_attack);

	//篡改后密文输出
	cout << "篡改后密文: " << ciphertext_attack << endl << endl;

	unsigncryption(ciphertext_attack, &flag_unsigncrytion, &de_plaintext, \
		& time_unsigncrytion, &flag_replay_attack, &flag_tamper_attack, &timestamp);
	*/


	/*
	//重放攻击
	printf("重放攻击\n");
	signcryption(plaintext, &flag_signcrytion, &ciphertext, &time_signcrytion);
	cout << "密文: " << ciphertext << endl;
	intercept_cipher(ciphertext, &flag_intercept, &intercepted_ciphertext);
	replay_attack(intercepted_ciphertext, &flag_do_replay, &ciphertext_attack);
	unsigncryption(ciphertext_attack, &flag_unsigncrytion, &de_plaintext, \
		& time_unsigncrytion, &flag_replay_attack, &flag_tamper_attack, &timestamp);
	getchar();
	*/

	return;
}
void signcryption(string plaintext, bool* flag_signcrytion, string* ciphertext, double* time_signcrytion)
{
	int state = 0;//状态变量，代表状态
	struct timeval start;
	gettimeofday(&start,0);
	message_st message_data;

	time_t time_tNow = time(NULL);
	char timeNowStr[TIMESTAMP_LEN] = { '\0' }; //时间戳
	sm2_sign_st sign;
	BIGNUM* r;
	BIGNUM* s;
	int pos;//加密后C的最终位置

	memset(&message_data, 0, sizeof(message_data));
	memset(&sign, 0, sizeof(sign));

	r = BN_new();
	s = BN_new();

	while (true) {
		switch (state)
		{
		case 0: //状态1，信息上加上时间戳，初始化，以及加密
			memset(message, '\0', MES_LEN);//清空字符串
			strcpy(message, plaintext.c_str());
			time_t2string(time_tNow, timeNowStr);
			strcat(message, timeNowStr);

			message_data.message = (BYTE*)message;
			message_data.message_byte_length = strlen((char*)message_data.message);
			message_data.klen_bit = message_data.message_byte_length * 8;
			sm2_hex2bin((BYTE*)sm2_param_k[ecp->type], message_data.k, ecp->point_byte_length);
			sm2_bn2bin(key_B->P->x, message_data.public_key.x, ecp->point_byte_length);
			sm2_bn2bin(key_B->P->y, message_data.public_key.y, ecp->point_byte_length);
			if (PRINT_MESSAGE) {
				//DEFINE_SHOW_BIGNUM(key_B->d);
				DEFINE_SHOW_BIGNUM(key_B->P->x);
				DEFINE_SHOW_BIGNUM(key_B->P->y);
			}

			/* enc-dec init end*/

			pos = sm2_encrypt_copy(ecp, &message_data);
			state = 1;
			break;
		case 1: //签名过程，初始化。
			/* sig-ver init begin */
			sm2_hex2bin((BYTE*)sm2_param_digest_k[ecp2->type], sign.k, ecp2->point_byte_length);
			sm2_bn2bin(key_A->d, sign.private_key, ecp2->point_byte_length);
			sm2_bn2bin(key_A->P->x, sign.public_key.x, ecp2->point_byte_length);
			sm2_bn2bin(key_A->P->y, sign.public_key.y, ecp2->point_byte_length);

			if (PRINT_MESSAGE) {
				DEFINE_SHOW_STRING(sign_array[i].public_key.x, ecp2_array[i]->point_byte_length);
				DEFINE_SHOW_STRING(sign_array[i].public_key.y, ecp2_array[i]->point_byte_length);
			}
			/* sig-ver init end */

			sm2_sign_modified(ecp2, &sign, &message_data);
			BN_bin2bn(sign.r, ecp->point_byte_length, r);
			if (BN_is_zero(r) == 1) //如果r是0的话，返回第一个状态
			{
				state = 0;
			}
			else
				state = 2;
			break;
		case 2:
			BN_bin2bn(sign.s, ecp->point_byte_length, s);
			if (BN_is_zero(s) == 1)
				state = 0;
			else
				state = 4;
			break;
		case 3://错误机制，加密失败，退出程序
			*flag_signcrytion = false;
			return;
		default:
			break;
		}
		if (state == 4) //退出循环
			break;
	}

	/* enc-dec free begin */

	//sm2_ec_key_free(key_B);
	//ec_param_free(ecp);

	/* sig-ver free begin */
	//sm2_ec_key_free(key_A);
	//ec_param_free(ecp2);
	/* sig-ver free end */

	*flag_signcrytion = true;
	//将r和s附在文件末尾
	BUFFER_APPEND_STRING(message_data.C, pos, ecp->point_byte_length, sign.r);
	BUFFER_APPEND_STRING(message_data.C, pos, ecp->point_byte_length, sign.s);

	charArray2hex(message_data.C, pos, ciphertext);
	struct timeval end;
	gettimeofday(&end,0);
	*time_signcrytion = (double)((end.tv_sec-start.tv_sec)*1000000+(end.tv_usec-start.tv_usec));
	return;
}
void unsigncryption(string ciphertext, bool* flag_unsigncrytion, string* plaintext, \
	double* time_unsigncrytion, bool* flag_replay_attack, bool* flag_tamper_attack, string* timestamp)
{
	*flag_replay_attack = false;
	*flag_tamper_attack = false;
	*flag_unsigncrytion = true;
	struct timeval start;
	gettimeofday(&start,0);
	//sm2_ec_key* key_B;
	//ec_param* ecp;
	message_st message_data;

	//ec_param* ecp2;
	//sm2_ec_key* key_A;
	sm2_sign_st sign;
	BIGNUM* r;
	BIGNUM* s;
	/*
	//初始化操作，同时将密文分片
	ecp = ec_param_new();
	ec_param_init(ecp, SM2_PARAM_IN, TYPE_IN, POINT_BIT_LENGTH_IN); //根据sm2_param参数初始化椭圆曲线参数

	key_B = sm2_ec_key_new(ecp); //根据参数初始化密钥B
	sm2_ec_key_init(key_B, sm2_param_d_B[ecp->type], ecp);

	ecp2 = ec_param_new();
	ec_param_init(ecp2, SM2_PARAM_IN, TYPE_IN, POINT_BIT_LENGTH_IN);

	key_A = sm2_ec_key_new(ecp2);
	sm2_ec_key_init(key_A, sm2_param_digest_d_A[ecp2->type], ecp2);//同时会生成私钥，待后续处理
	*/

	memset(&message_data, 0, sizeof(message_data));
	memset(&sign, 0, sizeof(sign));
	

	//message_data的初始化
	hex2charArray(message_data.C, ciphertext);
	//printf("%s\n", message_data.C);
	int C_length = ciphertext.length() / 2;
	// printf("%d\n",C_length);
	sm2_bn2bin(key_B->d, message_data.private_key, ecp->point_byte_length);//b的私钥
	message_data.message_byte_length = C_length - 1 - 4 * ecp->point_byte_length - HASH_BYTE_LENGTH;
	// printf("%d\n",message_data.message_byte_length);
	message_data.klen_bit = message_data.message_byte_length * 8;

	message_data.decrypt = (BYTE*)OPENSSL_malloc(message_data.message_byte_length + 1);
	// printf("%d\n",ecp->point_byte_length);
	memset(message_data.decrypt, '\0', message_data.message_byte_length + 1);

	int pos1 = 0;
	int pos2 = 0;
	BUFFER_APPEND_STRING(message_data.C_1, pos1, 1 + ecp->point_byte_length + ecp->point_byte_length, &message_data.C[pos2]);
	pos2 = pos2 + pos1;
	pos1 = 0;
	BUFFER_APPEND_STRING(message_data.C_2, pos1, message_data.message_byte_length, &message_data.C[pos2]);
	pos2 = pos2 + pos1;
	pos1 = 0;
	BUFFER_APPEND_STRING(message_data.C_3, pos1, HASH_BYTE_LENGTH, &message_data.C[pos2]);
	pos2 = pos2 + pos1;
	
	//sign初始化
	sm2_hex2bin((BYTE*)sm2_param_digest_k[ecp2->type], sign.k, ecp2->point_byte_length);
	//sm2_bn2bin(key_A->d, sign.private_key, ecp2->point_byte_length); //解签密过程不需要私钥
	sm2_bn2bin(key_A->P->x, sign.public_key.x, ecp->point_byte_length);//A的公钥
	sm2_bn2bin(key_A->P->y, sign.public_key.y, ecp->point_byte_length);
	memcpy(sign.r, &message_data.C[C_length - 2 * ecp->point_byte_length], ecp->point_byte_length);
	memcpy(sign.s, &message_data.C[C_length - ecp->point_byte_length], ecp->point_byte_length);

	//验证签名和解密
	sm2_verify_modified(ecp2, &sign, &message_data,flag_tamper_attack);
	if (*flag_tamper_attack == true)
	{
		*flag_unsigncrytion = false;
		OPENSSL_free(message_data.decrypt);
		return;
	}
	sm2_decrypt_copy(ecp, &message_data,flag_replay_attack,flag_tamper_attack);
	if (*flag_tamper_attack == true || *flag_replay_attack == true)
	{
		*flag_unsigncrytion = false;
		OPENSSL_free(message_data.decrypt);
		return;
	}

	char temp[MES_LEN] = { '\0' };
	strncpy(temp, (char*)message_data.decrypt, message_data.message_byte_length - 19);
	
	*plaintext = temp;
	*flag_unsigncrytion = true;
	*timestamp = (char*)message_data.decrypt + (message_data.message_byte_length - TIMESTAMP_LEN + 1);

	/* enc-dec free begin */
	//ec_param_free(ecp);
	//sm2_ec_key_free(key_A);
	/* enc-dec free end */


	/* sig-ver free begin */
	//ec_param_free(ecp2);
	//sm2_ec_key_free(key_B);
	/* sig-ver free end */

	OPENSSL_free(message_data.decrypt);

	struct timeval end;
	gettimeofday(&end,0);
	*time_unsigncrytion = (double)((end.tv_sec-start.tv_sec)*1000000+(end.tv_usec-start.tv_usec));
	return;
}

char char2hex(char i)
{
	if (i < 10) {
		return i + '0';
	}
	else {
		return i - 10 + 'A';
	}
}
char hex2char(char high, char low)
{
	char high_t, low_t;
	if (high >= 'A' && high <= 'Z')
		high_t = high - 'A'+10;
	else
		high_t = high - '0';
	if (low >= 'A' && low <= 'Z')
		low_t = low - 'A'+10;
	else
		low_t = low - '0';
	return (high_t << 4) | low_t;
}

void charArray2hex(BYTE* C, int length, string* ciphertext)
{
	int index = 0;
	char low, high;
	char temp[MES_LEN * 2] = { '\0' };
	char t;
	for (int i = 0; i < length; i++)
	{
		t = (char)C[i];
		low = t & 0x0F;
		high = (t & 0xF0)>>4;
		temp[index++] = char2hex(high);
		temp[index++] = char2hex(low);
	}
	*ciphertext = temp;
	return;
}

void hex2charArray(BYTE* C, string ciphertext)
{
	BYTE high, low;
	int index = 0;
	for (int i = 0; i < ciphertext.length(); i=i+2)
	{
		high = ciphertext[i];
		low = ciphertext[i+1];
		C[index++] = hex2char(high, low);
	}
	return;
}


//密文截获函数
void intercept_cipher(string ciphertext, bool* flag_intercept, string* intercepted_ciphertext)
{
	if (*flag_intercept)
	{
		char temp[MES_LEN * 2] = { '\0' };
		strcpy(temp, ciphertext.c_str());
		*intercepted_ciphertext = temp;
	}
	else
		*intercepted_ciphertext = "";
	return;
}
//密文篡改攻击函数,随机数
void tamper_attack(string intercepted_ciphertext, bool* flag_do_tamper, string* ciphertext) 
{
	srand(int(time(NULL)));
	char temp[MES_LEN * 2] = { '\0' };
	strcpy(temp,intercepted_ciphertext.c_str());
	if (intercepted_ciphertext == "")
		*flag_do_tamper = false;
	int length = intercepted_ciphertext.length(); //全文篡改
	vector<int> hasUsed;
	if (*flag_do_tamper)
	{
		int number = rand()% length;
		for (int i = 0; i < number; i++)
		{
			int index = rand() % length;
			if (find(hasUsed.begin(), hasUsed.end(), index) == hasUsed.end())
			{
				if(rand()%2==0)
				{
					temp[index] = (rand() % 6) +'A';
					hasUsed.push_back(index);
				}
				else
				{
					temp[index] = (rand() % 10) + '0';
					hasUsed.push_back(index);
				}
			}
			else
				i--;
		}
		*ciphertext = temp;
	}
	return;
}
//消息重放攻击函数，延迟发送
void replay_attack(string intercepted_ciphertext, bool* flag_do_replay, string* ciphertext)
{
	*ciphertext = intercepted_ciphertext;
	clock_t now = clock();
	if (intercepted_ciphertext == "")
		*flag_do_replay = false;
	if (*flag_do_replay) {
		while (clock() - now < DELAY_TIME);
	}
	return;
}

void gen_pub_from_pri_B(string private_key_str,string *public_B,sm2_ec_key* key_B)
{
	ecp = ec_param_new();
	ec_param_init(ecp, SM2_PARAM_IN, TYPE_IN, POINT_BIT_LENGTH_IN);
	key_B = sm2_ec_key_new(ecp);
	sm2_ec_key_init(key_B, (char*)private_key_str.c_str(), ecp);
	*public_B = BN_bn2hex(key_B->P->x);
	public_B->append((char *)BN_bn2hex(key_B->P->y));
}
void gen_pub_from_pri_A(string private_key_str,string *public_A,sm2_ec_key* key_A)
{
	ecp2 = ec_param_new();
	ec_param_init(ecp2, SM2_PARAM_IN, TYPE_IN, POINT_BIT_LENGTH_IN);
	key_A = sm2_ec_key_new(ecp2);
	sm2_ec_key_init(key_A, (char*)private_key_str.c_str(), ecp2);
	*public_A = BN_bn2hex(key_A->P->x);
	public_A->append((char*)BN_bn2hex(key_A->P->y));
}

void send_msg(string msg,char* ip_add,int port)
{
	int sockfd,n;
	char recvline[MAXLINE],sendline[MAXLINE];
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

	printf("send msg to server\n");
	printf("%s\n",msg.c_str());
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