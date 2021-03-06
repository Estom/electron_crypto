/*************************************************************************
		> File Name: sm2_test_param.c
		> Author:NEWPLAN
		> E-mail:newplan001@163.com
		> Created Time: Thu Apr 13 23:55:50 2017
 ************************************************************************/
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "sm2_test_param.h"
#include<openssl/ec.h>
#include"ec_param.h"
#include "sm2_ec_key.h"

 //�Ƽ����ߣ�
 //y2 = x3 + ax + b��
char* sm2_param_recommand[] =
{
	//p
	(char*)"FFFFFFFE" "FFFFFFFF" "FFFFFFFF" "FFFFFFFF" "FFFFFFFF" "00000000" "FFFFFFFF" "FFFFFFFF",
	//a
	(char*)"FFFFFFFE" "FFFFFFFF" "FFFFFFFF" "FFFFFFFF" "FFFFFFFF" "00000000" "FFFFFFFF" "FFFFFFFC",
	//b
	(char*)"28E9FA9E" "9D9F5E34" "4D5A9E4B" "CF6509A7" "F39789F5" "15AB8F92" "DDBCBD41" "4D940E93",
	//G_x
	(char*)"32C4AE2C" "1F198119" "5F990446" "6A39C994" "8FE30BBF" "F2660BE1" "715A4589" "334C74C7",
	//G_y
	(char*)"BC3736A2" "F4F6779C" "59BDCEE3" "6B692153" "D0A9877C" "C62A4740" "02DF32E5" "2139F0A0",
	//n
	(char*)"FFFFFFFE" "FFFFFFFF" "FFFFFFFF" "FFFFFFFF" "7203DF6B" "21C6052B" "53BBF409" "39D54123",
};

char* sm2_param_fp_192[] =
{
	//��Բ���߷���Ϊ��y2 = x3+ax+b
	//ʾ��1��Fp-192����
	//����p��
	(char*)"BDB6F4FE" "3E8B1D9E" "0DA8C0D4" "6F4C318C" "EFE4AFE3" "B6B8551F",
	//ϵ��a��
	(char*)"BB8E5E8F" "BC115E13" "9FE6A814" "FE48AAA6" "F0ADA1AA" "5DF91985",
	//ϵ��b��
	(char*)"1854BEBD" "C31B21B7" "AEFC80AB" "0ECD10D5" "B1B3308E" "6DBF11C1",
	//����G = (x;y)����׼�Ϊn��
	//����x��
	(char*)"4AD5F704" "8DE709AD" "51236DE6" "5E4D4B48" "2C836DC6" "E4106640",
	//����y��
	(char*)"02BB3A02" "D4AAADAC" "AE24817A" "4CA3A1B0" "14B52704" "32DB27D2",
	//��n��
	(char*)"BDB6F4FE" "3E8B1D9E" "0DA8C0D4" "0FC96219" "5DFAE76F" "56564677",
};

char* sm2_param_fp_256[] =
{
	//ʾ��2��Fp-256����
	//����p��
	(char*)"8542D69E" "4C044F18" "E8B92435" "BF6FF7DE" "45728391" "5C45517D" "722EDB8B" "08F1DFC3",
	//ϵ��a��
	(char*)"787968B4" "FA32C3FD" "2417842E" "73BBFEFF" "2F3C848B" "6831D7E0" "EC65228B" "3937E498",
	//ϵ��b��
	(char*)"63E4C6D3" "B23B0C84" "9CF84241" "484BFE48" "F61D59A5" "B16BA06E" "6E12D1DA" "27C5249A",
	//����G = (x;y)����׼�Ϊn��
	//����x��
	(char*)"421DEBD6" "1B62EAB6" "746434EB" "C3CC315E" "32220B3B" "ADD50BDC" "4C4E6C14" "7FEDD43D",
	//����y��
	(char*)"0680512B" "CBB42C07" "D47349D2" "153B70C4" "E5D7FDFC" "BFA36EA1" "A85841B9" "E46E09A2",
	//��n��
	(char*)"8542D69E" "4C044F18" "E8B92435" "BF6FF7DD" "29772063" "0485628D" "5AE74EE7" "C32E79B7",
};

char* sm2_param_f2m_193[] =
{
	//ʾ��3��F2m-193����
	//�������ɶ���ʽ��x193+x15+1 
	(char*)"2000000000000000000000000000000000000000000008001",
	//ϵ��a��
	(char*)"00",
	//ϵ��b��
	(char*)"00" "2FE22037" "B624DBEB" "C4C618E1" "3FD998B1" "A18E1EE0" "D05C46FB",
	//����G = (x;y)����׼�Ϊn��
	//����x��
	(char*)"00" "D78D47E8" "5C936440" "71BC1C21" "2CF994E4" "D21293AA" "D8060A84",
	//����y��
	(char*)"00" "615B9E98" "A31B7B2F" "DDEEECB7" "6B5D8755" "86293725" "F9D2FC0C",
	//��n��
	(char*)"80000000" "00000000" "00000000" "43E9885C" "46BF45D8" "C5EBF3A1",
};

char* sm2_param_f2m_257[] =
{
	//ʾ��4��F2m-257����
	//�������ɶ���ʽ��x257+x12+1
	(char*)"20000000000000000000000000000000000000000000000000000000000001001",
	//ϵ��a��
	(char*)"00",
	//ϵ��b��
	(char*)"00" "E78BCD09" "746C2023" "78A7E72B" "12BCE002" "66B9627E" "CB0B5A25" "367AD1AD" "4CC6242B",
	//����G = (x;y)����׼�Ϊn��
	//����x��
	(char*)"00" "CDB9CA7F" "1E6B0441" "F658343F" "4B10297C" "0EF9B649" "1082400A" "62E7A748" "5735FADD",
	//����y��
	(char*)"01" "3DE74DA6" "5951C4D7" "6DC89220" "D5F7777A" "611B1C38" "BAE260B1" "75951DC8" "060C2B3E",
	//��n��
	(char*)"7FFFFFFF" "FFFFFFFF" "FFFFFFFF" "FFFFFFFF" "BC972CF7" "E6B6F900" "945B3C6A" "0CF6161D",
};

char* sm2_param_d_B[2] =
{
	(char*)"1649AB77A00637BD5E2EFE283FBF353534AA7F7CB89463F208DDBC2920BB0DA0",
	(char*)"56A270D17377AA9A367CFA82E46FA5267713A9B91101D0777B07FCE018C757EB",
};

char* sm2_param_k[2] =
{
	(char*)"4C62EEFD6ECFC2B95B92FD6C3D9575148AFA17425546D49018E5388D49DD7B4F",
	(char*)"6D3B497153E3E92524E5C122682DBDC8705062E20B917A5F8FCDB8EE4C66663D",
};

char* sm2_param_digest_d_A[2] = 
{
	(char *)"128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263",
	(char*)"771EF3DB" "FF5F1CDC" "32B9C572" "93047619" "1998B2BF" "7CB981D7" "F5B39202" "645F0931",
};

char* sm2_param_digest_k[2] =
{
	(char*)"6CB28D99385C175C94F94E934817663FC176D925DD72B727260DBAAE1FB2F96F",
	(char*)"36CD79FC" "8E24B735" "7A8A7B4A" "46D454C3" "97703D64" "98158C60" "5399B341" "ADA186D6",
};

char* sm2_param_dh_d_A[2] =
{
	(char*)"6FCBA2EF" "9AE0AB90" "2BC3BDE3" "FF915D44" "BA4CC78F" "88E2F8E7" "F8996D3B" "8CCEEDEE",
	(char*)"4813903D" "254F2C20" "A94BC570" "42384969" "54BB5279" "F861952E" "F2C5298E" "84D2CEAA",
};
char* sm2_param_dh_r_A[2] =
{
	(char*)"83A2C9C8" "B96E5AF7" "0BD480B4" "72409A9A" "327257F1" "EBB73F5B" "073354B2" "48668563",
	(char*)"54A3D667" "3FF3A6BD" "6B02EBB1" "64C2A3AF" "6D4A4906" "229D9BFC" "E68CC366" "A2E64BA4",
};
char* sm2_param_dh_d_B[2] =
{
	(char*)"5E35D7D3" "F3C54DBA" "C72E6181" "9E730B01" "9A84208C" "A3A35E4C" "2E353DFC" "CB2A3B53",
	(char*)"08F41BAE" "0922F47C" "212803FE" "681AD52B" "9BF28A35" "E1CD0EC2" "73A2CF81" "3E8FD1DC",
};
char* sm2_param_dh_r_B[2] =
{
	(char*)"33FE2194" "0342161C" "55619C4A" "0C060293" "D543C80A" "F19748CE" "176D8347" "7DE71C80",
	(char*)"1F219333" "87BEF781" "D0A8F7FD" "708C5AE0" "A56EE3F4" "23DBC2FE" "5BDF6F06" "8C53F7AD",
};

char message[MES_LEN] = { '\0' };
char* message_digest = (char*)"message digest";

char* ID_A = (char*)"ALICE123@YAHOO.COM";
char* ID_B = (char*)"BILL456@YAHOO.COM";

//��Կ������������h
int sm2_param_dh_h[2] =
{
	1	, 4
};

ec_param* ecp = NULL;
ec_param* ecp2 = NULL;
sm2_ec_key* key_A = NULL;
sm2_ec_key* key_B = NULL;