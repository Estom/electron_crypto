#include <node_api.h>
#include <assert.h>
#include <iostream>
#include <string>
using namespace std;

//签密函数
void signcryption(string plaintext, bool *flag_signcrytion, string *ciphertext,
                  double *time_signcrytion);
//解签密函数
void unsigncryption(string ciphertext, bool *flag_unsigncrytion, string *plaintext,
                    double *time_unsigncrytion, bool *flag_replay_attack, bool *flag_tamper_attack, string *timestamp);
//密文截获函数
void intercept_cipher(string ciphertext, bool *flag_intercept, string *intercepted_ciphertext);
//密文篡改攻击函数
void tamper_attack(string intercepted_ciphertext, bool *flag_do_tamper, string *ciphertext_new);
//消息重放攻击函数
void replay_attack(string intercepted_ciphertext, bool *flag_do_replay, string *ciphertext);

int hello()
{
    //殷康龙负责调用函数
    //参数定义
    //公共参数
    string plaintext = "hreiwuyio";   //明文
    string ciphertext = "uwiouewiq0"; //密文
    //签密函数的参数
    double time_signcrytion = 0.89; //签密所用的时间（毫秒）
    bool flag_signcrytion = 0;      //签密是否成功
    //解签密函数的参数
    double time_unsigncrytion = 0.78; //解签密所用的时间（毫秒）
    bool flag_unsigncrytion = 0;      //解签密是否成功
    bool flag_replay_attack = 0;      //是否遭受了消息重放攻击
    bool flag_tamper_attack = 0;      //消息是否被篡改
    string timestamp = "723897";      //重放攻击中密文的时间戳
    //密文截获函数的参数
    string intercepted_ciphertext; //截获到的密文
    bool flag_intercept = 0;       //是否截获成功
    //密文篡改攻击函数的参数
    bool flag_do_tamper = 0; //是否进行密文篡改攻击
    string ciphertext_new;   //篡改后的密文
    //消息重放攻击函数的参数
    bool flag_do_replay = 0; //是否进行消息重放攻击

    //签密成功
    flag_signcrytion = 1;
    signcryption(plaintext, &flag_signcrytion, &ciphertext, &time_signcrytion);
    cout << "Signcryption successfully!" << endl;
    cout << "ciphertext: " << ciphertext << endl;
    cout << "time of signcrytion: " << time_signcrytion << endl;
    cout << endl;

    //签密失败
    flag_signcrytion = 0;
    signcryption(plaintext, &flag_signcrytion, &ciphertext, &time_signcrytion);
    cout << "Signcryption failed!" << endl;
    cout << endl;

    //解签密成功
    flag_unsigncrytion = 1;
    unsigncryption(ciphertext, &flag_unsigncrytion, &plaintext,
                   &time_unsigncrytion, &flag_replay_attack, &flag_tamper_attack, &timestamp);
    cout << "Unsigncryption successfully!" << endl;
    cout << "plaintext: " << plaintext << endl;
    cout << "time of unsigncrytion: " << time_unsigncrytion << endl;
    cout << endl;

    //解签密失败，发现遭受了消息重放攻击
    flag_unsigncrytion = 0;
    flag_do_replay = 1;
    flag_do_tamper = 0;
    unsigncryption(ciphertext, &flag_unsigncrytion, &plaintext,
                   &time_unsigncrytion, &flag_replay_attack, &flag_tamper_attack, &timestamp);
    cout << "Unsigncryption failed! Suffered a message replay attack!" << endl;
    cout << "Timestamp of ciphertext in message replay attack: " << timestamp << endl;
    cout << endl;

    //解签密失败，发现密文被篡改
    flag_unsigncrytion = 0;
    flag_do_replay = 0;
    flag_do_tamper = 1;
    unsigncryption(ciphertext, &flag_unsigncrytion, &plaintext,
                   &time_unsigncrytion, &flag_replay_attack, &flag_tamper_attack, &timestamp);
    cout << "Unsigncryption failed! The ciphertext has been tampered with!" << endl;
    cout << endl;

    return 0;
}
//肖晶晶负责实现函数
//签密函数
void signcryption(string plaintext, bool *flag_signcrytion, string *ciphertext, double *time_signcrytion)
{
    return;
}
//解签密函数
void unsigncryption(string ciphertext, bool *flag_unsigncrytion, string *plaintext,
                    double *time_unsigncrytion, bool *flag_replay_attack, bool *flag_tamper_attack, string *timestamp)
{
    return;
}
//密文截获函数
void intercept_cipher(string ciphertext, bool *flag_intercept, string *intercepted_ciphertext)
{
    *intercepted_ciphertext = ciphertext;
    return;
}
//密文篡改攻击函数
void tamper_attack(string intercepted_ciphertext, bool *flag_do_tamper, string *ciphertext_new)
{
    return;
}
//消息重放攻击函数
void replay_attack(string intercepted_ciphertext, bool *flag_do_replay, string *ciphertext)
{
    *ciphertext = intercepted_ciphertext;
    return;
}

napi_value signcryption_method(napi_env env, const napi_callback_info info)
{
    napi_value result;
    napi_status status;

    //创建返回对象
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

    //公共参数
    string plaintext = "test";  //明文
    string ciphertext = "test"; //密文
    //签密函数的参数
    double time_signcrytion = 0.89; //签密所用的时间（毫秒）
    bool flag_signcrytion = 0;      //签密是否成功

    //签密成功
    flag_signcrytion = 1;
    signcryption(plaintext, &flag_signcrytion, &ciphertext, &time_signcrytion);
    cout << "Signcryption successfully!" << endl;
    cout << "ciphertext: " << ciphertext << endl;
    cout << "time of signcrytion: " << time_signcrytion << endl;
    cout << endl;

    //签密失败
    flag_signcrytion = 0;
    signcryption(plaintext, &flag_signcrytion, &ciphertext, &time_signcrytion);
    cout << "Signcryption failed!" << endl;
    cout << endl;
}
napi_value unsigncryption_method(napi_env env, const napi_callback_info info)
{
    //公共参数
    string plaintext = "hreiwuyio";   //明文
    string ciphertext = "uwiouewiq0"; //密文
    //解签密函数的参数
    double time_unsigncrytion = 0.78; //解签密所用的时间（毫秒）
    bool flag_unsigncrytion = 0;      //解签密是否成功
    bool flag_replay_attack = 0;      //是否遭受了消息重放攻击
    bool flag_tamper_attack = 0;      //消息是否被篡改
    string timestamp = "723897";      //重放攻击中密文的时间戳

    //解签密成功
    flag_unsigncrytion = 1;
    unsigncryption(ciphertext, &flag_unsigncrytion, &plaintext,
                   &time_unsigncrytion, &flag_replay_attack, &flag_tamper_attack, &timestamp);
    cout << "Unsigncryption successfully!" << endl;
    cout << "plaintext: " << plaintext << endl;
    cout << "time of unsigncrytion: " << time_unsigncrytion << endl;
    cout << endl;

    //解签密失败，发现密文被篡改
    flag_unsigncrytion = 0;
    flag_do_replay = 0;
    flag_do_tamper = 1;
    unsigncryption(ciphertext, &flag_unsigncrytion, &plaintext,
                   &time_unsigncrytion, &flag_replay_attack, &flag_tamper_attack, &timestamp);
    cout << "Unsigncryption failed! The ciphertext has been tampered with!" << endl;
    cout << endl;
}
napi_value intercept_cipher_method(napi_env env, const napi_callback_info info)
{
    //密文截获函数的参数
    string intercepted_ciphertext; //截获到的密文
    bool flag_intercept = 0;       //是否截获成功
}
napi_value tamper_attack_method(napi_env env, const napi_callback_info info)
{
    //密文篡改攻击函数的参数
    bool flag_do_tamper = 0; //是否进行密文篡改攻击
    string ciphertext_new;   //篡改后的密文
}
napi_value replay_attack_method(napi_env env, const napi_callback_info info)
{
    //消息重放攻击函数的参数
    bool flag_do_replay = 0; //是否进行消息重放攻击
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
    return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, init)