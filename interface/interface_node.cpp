#include <node_api.h>
#include <assert.h>
#include <iostream>
#include <string>
#include "interface.h"
using namespace std;

// //函数声明
// //签密函数
// void signcryption(string plaintext, bool *flag_signcrytion, string *ciphertext,
//                   double *time_signcrytion);
// //解签密函数
// void unsigncryption(string ciphertext, bool *flag_unsigncrytion, string *plaintext,
//                     double *time_unsigncrytion, bool *flag_replay_attack, bool *flag_tamper_attack, string *timestamp);
// //密文截获函数
// void intercept_cipher(string ciphertext, bool *flag_intercept, string *intercepted_ciphertext);
// //密文篡改攻击函数
// void tamper_attack(string intercepted_ciphertext, bool *flag_do_tamper, string *ciphertext_new);
// //消息重放攻击函数
// void replay_attack(string intercepted_ciphertext, bool *flag_do_replay, string *ciphertext);

//函数的调用示例
// int example()
// {
//     //殷康龙负责调用函数

//     //参数定义
//     //公共参数
//     //string plaintext = "hreiwuyio";//明文
//     //string ciphertext = "uwiouewiq0";//密文

//     //签密的参数
//     string plaintext_signcrytion = "hreiwuyio";   //需要签密的明文
//     string ciphertext_signcrytion = "uwiouewiq0"; //签密产生的密文
//     double time_signcrytion = 0.89;               //签密所用的时间（毫秒）
//     bool flag_signcrytion = 0;                    //签密是否成功

//     //解签密的参数
//     string plaintext_unsigncrytion = "hreiwuyio";   //解签密产生的明文
//     string ciphertext_unsigncrytion = "uwiouewiq0"; //需要解签密的密文
//     double time_unsigncrytion = 0.78;               //解签密所用的时间（毫秒）
//     bool flag_unsigncrytion = 0;                    //解签密是否成功
//     bool flag_replay_attack = 0;                    //是否遭受了消息重放攻击
//     bool flag_tamper_attack = 0;                    //消息是否被篡改
//     string timestamp = "723897";                    //重放攻击中密文的时间戳

//     //密文截获的参数
//     string intercepted_ciphertext; //截获到的密文
//     bool flag_intercept = 0;       //是否截获成功

//     //密文篡改攻击的参数
//     bool flag_do_tamper = 0; //是否进行密文篡改攻击
//     string ciphertext_new;   //篡改后的密文

//     //消息重放攻击的参数
//     bool flag_do_replay = 0; //是否进行消息重放攻击

//     //签密者A所做的操作
//     //1、输入明文
//     //2、签密
//     //签密成功
//     flag_signcrytion = 1;
//     signcryption(plaintext_signcrytion, &flag_signcrytion, &ciphertext_signcrytion, &time_signcrytion);
//     cout << "Signcryption successfully!" << endl;
//     cout << "ciphertext: " << ciphertext_signcrytion << endl;
//     cout << "time of signcrytion: " << time_signcrytion << endl;
//     cout << endl;
//     //签密失败
//     flag_signcrytion = 0;
//     signcryption(plaintext_signcrytion, &flag_signcrytion, &ciphertext_signcrytion, &time_signcrytion);
//     cout << "Signcryption failed!" << endl;
//     cout << endl;
//     //3、发送密文给用户B
//     ciphertext_unsigncrytion = ciphertext_signcrytion;

//     //解签密者B所做的操作
//     //解签密
//     //解签密成功
//     flag_unsigncrytion = 1;
//     flag_replay_attack = 0;
//     flag_tamper_attack = 0;
//     unsigncryption(ciphertext_unsigncrytion, &flag_unsigncrytion, &plaintext_unsigncrytion,
//                    &time_unsigncrytion, &flag_replay_attack, &flag_tamper_attack, &timestamp);
//     cout << "Unsigncryption successfully!" << endl;
//     cout << "Has the ciphertext been tampered with?" << flag_tamper_attack << endl;
//     cout << "Has the ciphertext been replayed?" << flag_replay_attack << endl;
//     cout << "plaintext: " << plaintext_unsigncrytion << endl;
//     cout << "time of unsigncrytion: " << time_unsigncrytion << endl;
//     cout << endl;
//     //解签密失败，发现遭受了消息重放攻击
//     flag_unsigncrytion = 0;
//     flag_replay_attack = 1;
//     flag_tamper_attack = 0;
//     unsigncryption(ciphertext_unsigncrytion, &flag_unsigncrytion, &plaintext_unsigncrytion,
//                    &time_unsigncrytion, &flag_replay_attack, &flag_tamper_attack, &timestamp);
//     cout << "Unsigncryption failed! Suffered a message replay attack!" << endl;
//     cout << "Has the ciphertext been tampered with? " << flag_tamper_attack << endl;
//     cout << "Has the ciphertext been replayed? " << flag_replay_attack << endl;
//     cout << "Timestamp of ciphertext in message replay attack: " << timestamp << endl;
//     cout << endl;
//     //解签密失败，发现密文被篡改
//     flag_unsigncrytion = 0;
//     flag_replay_attack = 0;
//     flag_tamper_attack = 1;
//     unsigncryption(ciphertext_unsigncrytion, &flag_unsigncrytion, &plaintext_unsigncrytion,
//                    &time_unsigncrytion, &flag_replay_attack, &flag_tamper_attack, &timestamp);
//     cout << "Unsigncryption failed! The ciphertext has been tampered with!" << endl;
//     cout << "Has the ciphertext been tampered with? " << flag_tamper_attack << endl;
//     cout << "Has the ciphertext been replayed? " << flag_replay_attack << endl;
//     cout << endl;

//     //篡改攻击者C所做的操作
//     //1、截获密文并截获成功
//     flag_intercept = 1;
//     intercept_cipher(ciphertext_signcrytion, &flag_intercept, &intercepted_ciphertext);
//     cout << "Intercepted ciphertext: " << intercepted_ciphertext << endl;
//     //2、对密文进行篡改
//     flag_do_tamper = 1;
//     tamper_attack(intercepted_ciphertext, &flag_do_tamper, &ciphertext_new);
//     cout << "Ciphertext after tampering: " << ciphertext_new << endl;
//     //3、把篡改后得到的新密文发给解签密者B
//     ciphertext_unsigncrytion = ciphertext_new;
//     cout << endl;

//     //消息重放攻击者D所做的操作
//     //1、截获密文并截获成功
//     flag_intercept = 1;
//     intercept_cipher(ciphertext_signcrytion, &flag_intercept, &intercepted_ciphertext);
//     cout << "Intercepted ciphertext: " << intercepted_ciphertext << endl;
//     //2、对密文进行重放，即把截获的密文发送给解签密者B
//     flag_do_replay = 1;
//     replay_attack(intercepted_ciphertext, &flag_do_replay, &ciphertext_unsigncrytion);

//     return 0;
// }
// //肖晶晶负责实现函数
// //签密函数
// void signcryption(string plaintext, bool *flag_signcrytion, string *ciphertext, double *time_signcrytion)
// {
//     *flag_signcrytion = true;
//     *ciphertext = plaintext + "_signcryption";
//     *time_signcrytion = 3.14;
//     return;
// }
// //解签密函数
// void unsigncryption(string ciphertext, bool *flag_unsigncrytion, string *plaintext,
//                     double *time_unsigncrytion, bool *flag_replay_attack, bool *flag_tamper_attack, string *timestamp)
// {
//     *flag_replay_attack = true;
//     *flag_unsigncrytion = true;
//     *flag_tamper_attack = true;

//     *plaintext = ciphertext + "_unsign";
//     *timestamp = "12345678";
//     *time_unsigncrytion = 4.123;
//     return;
// }
// //密文截获函数
// void intercept_cipher(string ciphertext, bool *flag_intercept, string *intercepted_ciphertext)
// {
//     *flag_intercept = true;
//     *intercepted_ciphertext = ciphertext + "_intercepted";
//     return;
// }
// //密文篡改攻击函数
// void tamper_attack(string intercepted_ciphertext, bool *flag_do_tamper, string *ciphertext_new)
// {
//     *flag_do_tamper=1;
//     *ciphertext_new=intercepted_ciphertext+"_tamper";
//     return;
// }
// //消息重放攻击函数
// void replay_attack(string intercepted_ciphertext, bool *flag_do_replay, string *ciphertext)
// {
//     *flag_do_replay=1;
//     *ciphertext = intercepted_ciphertext+"_replay";
//     return;
// }

napi_value signcryption_method(napi_env env, const napi_callback_info info)
{
    //创建返回对象和状态对象
    napi_value result;
    napi_status status;

    status = napi_create_object(env, &result);
    assert(status == napi_ok);

    //获得1个参数messge
    size_t argc = 1;
    napi_value args[1];
    status = napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    assert(status == napi_ok);
    if (argc < 1)
    {
        napi_throw_type_error(env, nullptr, "Wrong number of arguments");
        return nullptr;
    }
    //将message转换为c类型的数据
    size_t length = 0;
    status = napi_get_value_string_utf8(env, args[0], NULL, 0, &length);
    assert(status == napi_ok);
    char *buff = (char *)malloc(255);
    status = napi_get_value_string_utf8(env, args[0], buff, length + 1, &length);
    assert(status == napi_ok);
    buff[length] = '\0';

    //调用签密函数
    string plaintext = buff;        //明文
    string ciphertext = "test";     //密文
    string time_signcrytion = "0.999"; //签密所用的时间（毫秒）
    bool flag_signcrytion = 0;      //签密是否成功
    signcryption(plaintext, &flag_signcrytion, &ciphertext, &time_signcrytion);

    //类型转换
    napi_value _flag_signcrytion, _ciphertext, _time_signcrytion;
    status = napi_create_int32(env, flag_signcrytion, &_flag_signcrytion);
    assert(status == napi_ok);

    status = napi_create_string_utf8(env, ciphertext.c_str(), ciphertext.length(), &_ciphertext);
    assert(status == napi_ok);
    
    status = napi_create_string_utf8(env, time_signcrytion.c_str(), time_signcrytion.length(), &_time_signcrytion);
    assert(status == napi_ok);

    // status = napi_create_double(env, time_signcrytion, &_time_signcrytion);
    // assert(status == napi_ok);

    //构造返回值
    status = napi_set_named_property(env, result, "flag_signcrytion", _flag_signcrytion);
    assert(status == napi_ok);
    status = napi_set_named_property(env, result, "ciphertext", _ciphertext);
    assert(status == napi_ok);
    status = napi_set_named_property(env, result, "time_signcrytion", _time_signcrytion);
    assert(status == napi_ok);

    return result;
}
napi_value unsigncryption_method(napi_env env, const napi_callback_info info)
{
    //创建返回对象和状态对象
    napi_value result;
    napi_status status;

    status = napi_create_object(env, &result);
    assert(status == napi_ok);

    //调用解签密函数
    string plaintext;          //明文
    string time_unsigncrytion; //解签密所用的时间（毫秒）
    bool flag_unsigncrytion;      //解签密是否成功
    bool flag_replay_attack;      //是否遭受了消息重放攻击
    bool flag_tamper_attack;      //消息是否被篡改
    string timestamp;      //重放攻击中密文的时间戳
    flag_unsigncrytion = 1;
    unsigncryption(&flag_unsigncrytion, &plaintext,
                   &time_unsigncrytion, &flag_replay_attack, &flag_tamper_attack, &timestamp);
    //类型转换
    napi_value _flag_unsigncrytion, _plaintext, _time_unsigncrytion, _flag_replay_attack, _flag_tamper_attack, _timestamp;
    status = napi_create_int32(env, flag_unsigncrytion, &_flag_unsigncrytion);
    assert(status == napi_ok);
    status = napi_create_int32(env, flag_replay_attack, &_flag_replay_attack);
    assert(status == napi_ok);
    status = napi_create_int32(env, flag_tamper_attack, &_flag_tamper_attack);
    assert(status == napi_ok);

    status = napi_create_string_utf8(env, plaintext.c_str(), plaintext.length(), &_plaintext);
    assert(status == napi_ok);
    status = napi_create_string_utf8(env, timestamp.c_str(), timestamp.length(), &_timestamp);
    assert(status == napi_ok);

    status = napi_create_string_utf8(env, time_unsigncrytion.c_str(), time_unsigncrytion.length(), &_time_unsigncrytion);
    assert(status == napi_ok);
    // status = napi_create_double(env, time_unsigncrytion, &_time_unsigncrytion);
    // assert(status == napi_ok);

    //构造返回值
    status = napi_set_named_property(env, result, "flag_unsigncrytion", _flag_unsigncrytion);
    assert(status == napi_ok);
    status = napi_set_named_property(env, result, "flag_replay_attack", _flag_replay_attack);
    assert(status == napi_ok);
    status = napi_set_named_property(env, result, "flag_tamper_attack", _flag_tamper_attack);
    assert(status == napi_ok);
    status = napi_set_named_property(env, result, "plaintext", _plaintext);
    assert(status == napi_ok);
    status = napi_set_named_property(env, result, "timestamp", _timestamp);
    assert(status == napi_ok);
    status = napi_set_named_property(env, result, "time_unsigncrytion", _time_unsigncrytion);
    assert(status == napi_ok);

    return result;
}
napi_value intercept_cipher_method(napi_env env, const napi_callback_info info)
{
    //创建返回对象和状态对象
    napi_value result;
    napi_status status;

    status = napi_create_object(env, &result);
    assert(status == napi_ok);

    //获得1个参数messge
    size_t argc = 1;
    napi_value args[1];
    status = napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    assert(status == napi_ok);
    if (argc < 1)
    {
        napi_throw_type_error(env, nullptr, "Wrong number of arguments");
        return nullptr;
    }
    //将message转换为c类型的数据
    size_t length = 0;
    status = napi_get_value_string_utf8(env, args[0], NULL, 0, &length);
    assert(status == napi_ok);
    char *buff = (char *)malloc(8000);
    status = napi_get_value_string_utf8(env, args[0], buff, length + 1, &length);
    assert(status == napi_ok);
    buff[length] = '\0';

    //密文截获函数的参数
    string ciphertext_signcrytion = buff; //签密产生的密文
    string intercepted_ciphertext;        //截获到的密文
    bool flag_intercept = 1;              //是否截获成功
    intercept_cipher(ciphertext_signcrytion, &flag_intercept, &intercepted_ciphertext);

    //类型转换
    napi_value _flag_intercept, _intercepted_ciphertext;
    status = napi_create_int32(env, flag_intercept, &_flag_intercept);
    assert(status == napi_ok);

    status = napi_create_string_utf8(env, intercepted_ciphertext.c_str(), intercepted_ciphertext.length(), &_intercepted_ciphertext);
    assert(status == napi_ok);

    // 构造返回值
    status = napi_set_named_property(env, result, "flag_intercept", _flag_intercept);
    assert(status == napi_ok);
    status = napi_set_named_property(env, result, "intercepted_ciphertext", _intercepted_ciphertext);
    assert(status == napi_ok);
    return result;
}
napi_value tamper_attack_method(napi_env env, const napi_callback_info info)
{
    //创建返回对象和状态对象
    napi_value result;
    napi_status status;

    status = napi_create_object(env, &result);
    assert(status == napi_ok);

    //获得1个参数messge
    size_t argc = 1;
    napi_value args[1];
    status = napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    assert(status == napi_ok);
    if (argc < 1)
    {
        napi_throw_type_error(env, nullptr, "Wrong number of arguments");
        return nullptr;
    }
    //将message转换为c类型的数据
    size_t length = 0;
    status = napi_get_value_string_utf8(env, args[0], NULL, 0, &length);
    assert(status == napi_ok);
    char *buff = (char *)malloc(8000);
    status = napi_get_value_string_utf8(env, args[0], buff, length + 1, &length);
    assert(status == napi_ok);
    buff[length] = '\0';

    //密文篡改攻击函数的参数
    string intercepted_ciphertext = buff;
    bool flag_do_tamper = 1; //是否进行密文篡改攻击
    string ciphertext_new;   //篡改后的密文
    tamper_attack(intercepted_ciphertext, &flag_do_tamper, &ciphertext_new);

    //类型转换
    napi_value _flag_do_tamper, _ciphertext_new;
    status = napi_create_int32(env, flag_do_tamper, &_flag_do_tamper);
    assert(status == napi_ok);

    status = napi_create_string_utf8(env, ciphertext_new.c_str(), ciphertext_new.length(), &_ciphertext_new);
    assert(status == napi_ok);

    // 构造返回值
    status = napi_set_named_property(env, result, "flag_do_tamper", _flag_do_tamper);
    assert(status == napi_ok);
    status = napi_set_named_property(env, result, "ciphertext_new", _ciphertext_new);
    assert(status == napi_ok);
    return result;
}
napi_value replay_attack_method(napi_env env, const napi_callback_info info)
{
    //创建返回对象和状态对象
    napi_value result;
    napi_status status;

    status = napi_create_object(env, &result);
    assert(status == napi_ok);

    //获得1个参数messge
    size_t argc = 1;
    napi_value args[1];
    status = napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    assert(status == napi_ok);
    if (argc < 1)
    {
        napi_throw_type_error(env, nullptr, "Wrong number of arguments");
        return nullptr;
    }
    //将message转换为c类型的数据
    size_t length = 0;
    status = napi_get_value_string_utf8(env, args[0], NULL, 0, &length);
    assert(status == napi_ok);
    char *buff = (char *)malloc(8000);
    status = napi_get_value_string_utf8(env, args[0], buff, length + 1, &length);
    assert(status == napi_ok);
    buff[length] = '\0';

    //消息重放攻击函数的参数
    string intercepted_ciphertext = buff;
    bool flag_do_replay = 1; //是否进行消息重放攻击
    string ciphertext_unsigncrytion = "fjie";
    replay_attack(intercepted_ciphertext, &flag_do_replay, &ciphertext_unsigncrytion);

    //类型转换
    napi_value _flag_do_replay, _ciphertext_unsigncrytion;
    status = napi_create_int32(env, flag_do_replay, &_flag_do_replay);
    assert(status == napi_ok);

    status = napi_create_string_utf8(env, ciphertext_unsigncrytion.c_str(), ciphertext_unsigncrytion.length(), &_ciphertext_unsigncrytion);
    assert(status == napi_ok);

    // 构造返回值
    status = napi_set_named_property(env, result, "flag_do_replay", _flag_do_replay);
    assert(status == napi_ok);
    status = napi_set_named_property(env, result, "ciphertext_unsigncrytion", _ciphertext_unsigncrytion);
    assert(status == napi_ok);
    return result;
}
napi_value generate_A(napi_env env, const napi_callback_info info){
    //创建返回对象和状态对象
    napi_value result;
    napi_status status;

    status = napi_create_object(env, &result);
    assert(status == napi_ok);

    //获得1个参数messge
    size_t argc = 1;
    napi_value args[1];
    status = napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    assert(status == napi_ok);
    if (argc < 1)
    {
        napi_throw_type_error(env, nullptr, "Wrong number of arguments");
        return nullptr;
    }
    //将message转换为c类型的数据
    size_t length = 0;
    status = napi_get_value_string_utf8(env, args[0], NULL, 0, &length);
    assert(status == napi_ok);
    char *buff = (char *)malloc(8000);
    status = napi_get_value_string_utf8(env, args[0], buff, length + 1, &length);
    assert(status == napi_ok);
    buff[length] = '\0';

    //秘钥生成的函数
    string private_A = buff;
    string public_A;
    gen_pub_from_pri_A(private_A,&public_A);

    //类型转换
    napi_value _public_A;
    status = napi_create_string_utf8(env, public_A.c_str(), public_A.length(), &_public_A);
    assert(status == napi_ok);

    //构造返回值
    status = napi_set_named_property(env, result, "public_A", _public_A);
    assert(status == napi_ok);
    return result;
}

napi_value generate_B(napi_env env, const napi_callback_info info){
    //创建返回对象和状态对象
    napi_value result;
    napi_status status;

    status = napi_create_object(env, &result);
    assert(status == napi_ok);

    //获得1个参数messge
    size_t argc = 1;
    napi_value args[1];
    status = napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    assert(status == napi_ok);
    if (argc < 1)
    {
        napi_throw_type_error(env, nullptr, "Wrong number of arguments");
        return nullptr;
    }
    //将message转换为c类型的数据
    size_t length = 0;
    status = napi_get_value_string_utf8(env, args[0], NULL, 0, &length);
    assert(status == napi_ok);
    char *buff = (char *)malloc(8000);
    status = napi_get_value_string_utf8(env, args[0], buff, length + 1, &length);
    assert(status == napi_ok);
    buff[length] = '\0';

    //秘钥生成的函数
    string private_B = buff;
    string public_B;
    gen_pub_from_pri_B(private_B,&public_B);

    //类型转换
    napi_value _public_B;
    status = napi_create_string_utf8(env, public_B.c_str(), public_B.length(), &_public_B);
    assert(status == napi_ok);

    //构造返回值
    status = napi_set_named_property(env, result, "public_B", _public_B);
    assert(status == napi_ok);
    return result;
}

/*socket 通信相关的内容*/
napi_value init_server_method(napi_env env, const napi_callback_info info){
    //创建返回对象和状态对象
    napi_value result;
    napi_status status;

    status = napi_create_object(env, &result);
    assert(status == napi_ok);

    //秘钥生成的函数
    initial_server();

    return result;
}


napi_value send_signal_A_method(napi_env env, const napi_callback_info info){
    //创建返回对象和状态对象
    napi_value result;
    napi_status status;

    status = napi_create_object(env, &result);
    assert(status == napi_ok);

    bool flag_replay = false;
    bool flag_tamper = false;

    //秘钥生成的函数
    send_signal_A(flag_replay,flag_tamper);
	// re_B_ciphertext(listenBfd,&ciphertext_B);

    return result;
}
napi_value receive_signal_B_method(napi_env env, const napi_callback_info info){
    //创建返回对象和状态对象
    napi_value result;
    napi_status status;

    status = napi_create_object(env, &result);
    assert(status == napi_ok);

    string ciphertext_B;
    //B 接收信号
    // send_signal_A(flag_replay,flag_tamper);
	receive_B(&ciphertext_B);

    //类型转换
    napi_value _ciphertext_B;
    status = napi_create_string_utf8(env, ciphertext_B.c_str(), ciphertext_B.length(), &_ciphertext_B);
    assert(status == napi_ok);

    //构造返回值
    status = napi_set_named_property(env, result, "ciphertext_B", _ciphertext_B);
    assert(status == napi_ok);
    return result;
}

napi_value init(napi_env env, napi_value exports)
{
    napi_status status;
    // napi_value new_exports;
    napi_value fn_signcryption_method;
    napi_value fn_unsigncryption_method;
    napi_value fn_intercept_cipher_method;
    napi_value fn_tamper_attack_method;
    napi_value fn_replay_attack_method;
    napi_value fn_generate_A_method;
    napi_value fn_generate_B_method;
    napi_value fn_init_server_method;
    napi_value fn_send_signal_A_method;
    napi_value fn_receive_signal_B_method;

    //创建了一个NAPI方法，然后直接返回这个方法。那么这个模块本身也就对应这个方法
    status = napi_create_function(env, nullptr, NAPI_AUTO_LENGTH, signcryption_method, nullptr, &fn_signcryption_method);
    assert(status == napi_ok);
    status = napi_set_named_property(env, exports, "signcryption", fn_signcryption_method);
    assert(status == napi_ok);

    //在exports暴露的接口中，绑定其他的方法。模块的hello属性，是一个方法。
    status = napi_create_function(env, nullptr, NAPI_AUTO_LENGTH, unsigncryption_method, nullptr, &fn_unsigncryption_method);
    assert(status == napi_ok);
    status = napi_set_named_property(env, exports, "unsigncryption", fn_unsigncryption_method);
    assert(status == napi_ok);

    //在exports暴露的接口中，绑定其他的方法。模块的hello属性，是一个方法。
    status = napi_create_function(env, nullptr, NAPI_AUTO_LENGTH, intercept_cipher_method, nullptr, &fn_intercept_cipher_method);
    assert(status == napi_ok);
    status = napi_set_named_property(env, exports, "intercept_cipher", fn_intercept_cipher_method);
    assert(status == napi_ok);

    //在exports暴露的接口中，绑定其他的方法。模块的hello属性，是一个方法。
    status = napi_create_function(env, nullptr, NAPI_AUTO_LENGTH, tamper_attack_method, nullptr, &fn_tamper_attack_method);
    assert(status == napi_ok);
    status = napi_set_named_property(env, exports, "tamper_attack", fn_tamper_attack_method);
    assert(status == napi_ok);

    //在exports暴露的接口中，绑定其他的方法。模块的hello属性，是一个方法。
    status = napi_create_function(env, nullptr, NAPI_AUTO_LENGTH, replay_attack_method, nullptr, &fn_replay_attack_method);
    assert(status == napi_ok);
    status = napi_set_named_property(env, exports, "replay_attack", fn_replay_attack_method);
    assert(status == napi_ok);
    //在exports暴露的接口中，绑定其他的方法。模块的hello属性，是一个方法。
    status = napi_create_function(env, nullptr, NAPI_AUTO_LENGTH, generate_A, nullptr, &fn_generate_A_method);
    assert(status == napi_ok);
    status = napi_set_named_property(env, exports, "generate_A", fn_generate_A_method);
    assert(status == napi_ok);
    //在exports暴露的接口中，绑定其他的方法。模块的hello属性，是一个方法。
    status = napi_create_function(env, nullptr, NAPI_AUTO_LENGTH, generate_B, nullptr, &fn_generate_B_method);
    assert(status == napi_ok);
    status = napi_set_named_property(env, exports, "generate_B", fn_generate_B_method);
    assert(status == napi_ok);

    //在exports暴露的接口中，绑定其他的方法。模块的hello属性，是一个方法。
    status = napi_create_function(env, nullptr, NAPI_AUTO_LENGTH, init_server_method, nullptr, &fn_init_server_method);
    assert(status == napi_ok);
    status = napi_set_named_property(env, exports, "init_server", fn_init_server_method);
    assert(status == napi_ok);

    //在exports暴露的接口中，绑定其他的方法。模块的hello属性，是一个方法。
    status = napi_create_function(env, nullptr, NAPI_AUTO_LENGTH, send_signal_A_method, nullptr, &fn_send_signal_A_method);
    assert(status == napi_ok);
    status = napi_set_named_property(env, exports, "send_signal_A", fn_send_signal_A_method);
    assert(status == napi_ok);

    //在exports暴露的接口中，绑定其他的方法。模块的hello属性，是一个方法。
    status = napi_create_function(env, nullptr, NAPI_AUTO_LENGTH, receive_signal_B_method, nullptr, &fn_receive_signal_B_method);
    assert(status == napi_ok);
    status = napi_set_named_property(env, exports, "receive_signal_B", fn_receive_signal_B_method);
    assert(status == napi_ok);
    return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, init) 