const sm2 = require('./build/Release/sm2');
//测试init函数
console.log("init_server函数测试")
sm2.init_server()
console.log("init_server测试完成")

//测试秘钥函数
console.log("秘钥函数测试：")
var public_A = sm2.generate_A("128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263")
console.log(public_A.public_A);
console.log("秘钥函数测试：")
var public_B = sm2.generate_B("1649AB77A00637BD5E2EFE283FBF353534AA7F7CB89463F208DDBC2920BB0DA0")
console.log(public_B.public_B);

//测试加密函数
console.log("签密函数测试：")
var sign_result = sm2.signcryption("hello");
console.log(sign_result.flag_signcrytion);
console.log(sign_result.ciphertext);
console.log(sign_result.time_signcrytion);

// //测试发送函数
console.log("测试发送函数：")
sm2.send_signal_A()
console.log("发送函数测试完成")
//测试接收函数
console.log("接收函数：")
var receive_result = sm2.receive_signal_B()
console.log(receive_result.ciphertext_B)
console.log("接收函数结束")

//解签密函数
console.log("解签密函数测试：");
var unsign_result = sm2.unsigncryption()
console.log("11111111")
console.log(unsign_result.flag_unsigncrytion);
console.log(unsign_result.flag_replay_attack);
console.log(unsign_result.flag_tamper_attack);
console.log(unsign_result.plaintext);
console.log(unsign_result.timestamp);
console.log(unsign_result.time_unsigncrytion);

//截获函数
console.log("截获函数：")
var intercept_result = sm2.intercept_cipher("0411C88AE04CEC1BA554D03D5B5970333A83585826C2A985DE5520D9E934389EFB84B52D344FB21AA8EA38A4940C8332692B8D4DA2393549212EAFDC0F11CA5C9CCA17BA971755E9274F3D74F51C9ED37408FE0BE0CDADCDE6984AA88DB97CCA14963671AB4645A48F63528228571DEE6DA70758868A4560536E05DBD16203CE9DCE63E543BD0718094942505554E14C8458566BDBF5CA132F290247C50C75C795185BAFC02AB267F24324F1E241E2412B5F1F4DBEEE131659")
console.log(intercept_result.flag_intercept);
console.log(intercept_result.intercepted_ciphertext);

// //篡改函数
// console.log("篡改攻击：")
// var tamper_result = sm2.tamper_attack("0411C88AE04CEC1BA554D03D5B5970333A83585826C2A985DE5520D9E934389EFB84B52D344FB21AA8EA38A4940C8332692B8D4DA2393549212EAFDC0F11CA5C9CCA17BA971755E9274F3D74F51C9ED37408FE0BE0CDADCDE6984AA88DB97CCA14963671AB4645A48F63528228571DEE6DA70758868A4560536E05DBD16203CE9DCE63E543BD0718094942505554E14C8458566BDBF5CA132F290247C50C75C795185BAFC02AB267F24324F1E241E2412B5F1F4DBEEE131659")
// console.log(tamper_result.flag_do_tamper);
// console.log(tamper_result.ciphertext_new);

// //截获函数
// console.log("重放攻击：")
// var replay_result = sm2.replay_attack("0411C88AE04CEC1BA554D03D5B5970333A83585826C2A985DE5520D9E934389EFB84B52D344FB21AA8EA38A4940C8332692B8D4DA2393549212EAFDC0F11CA5C9CCA17BA971755E9274F3D74F51C9ED37408FE0BE0CDADCDE6984AA88DB97CCA14963671AB4645A48F63528228571DEE6DA70758868A4560536E05DBD16203CE9DCE63E543BD0718094942505554E14C8458566BDBF5CA132F290247C50C75C795185BAFC02AB267F24324F1E241E2412B5F1F4DBEEE131659")
// console.log(replay_result.flag_do_replay);
// console.log(replay_result.ciphertext_unsigncrytion);