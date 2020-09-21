const sm2 = require('./build/Release/sm2');

// 测试加密函数
var sign_result = sm2.signcryption("hello");
console.log("签密函数测试：")
console.log(sign_result.flag_signcrytion);
console.log(sign_result.ciphertext);
console.log(sign_result.time_signcrytion);

//解签密函数
var unsign_result = sm2.unsigncryption("balabala")
console.log("解签密函数测试：");
console.log(unsign_result.flag_unsigncrytion);
console.log(unsign_result.flag_replay_attack);
console.log(unsign_result.flag_tamper_attack);
console.log(unsign_result.plaintext);
console.log(unsign_result.timestamp);
console.log(unsign_result.time_unsigncrytion);

//截获函数
var intercept_result = sm2.intercept_cipher("hahaha")
console.log("截获函数：")
console.log(intercept_result.flag_intercept);
console.log(intercept_result.intercepted_ciphertext);

//截获函数
var tamper_result = sm2.tamper_attack("lueluelue")
console.log("篡改攻击：")
console.log(tamper_result.flag_do_tamper);
console.log(tamper_result.ciphertext_new);

//截获函数
var replay_result = sm2.replay_attack("yingyingying")
console.log("重放攻击：")
console.log(replay_result.flag_do_replay);
console.log(replay_result.ciphertext_unsigncrytion);


