const sm2 = require('./build/Release/sm2');

//测试秘钥函数
var public_A = sm2.generate_A("128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263")
console.log("秘钥函数测试：")
console.log(public_A.public_A);
var public_B = sm2.generate_B("128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263")
console.log("秘钥函数测试：")
console.log(public_B.public_B);

//测试加密函数
var sign_result = sm2.signcryption("hello");
console.log("签密函数测试：")
console.log(sign_result.flag_signcrytion);
console.log(sign_result.ciphertext);
console.log(sign_result.time_signcrytion);

// //解签密函数
// var unsign_result = sm2.unsigncryption("0411C88AE04CEC1BA554D03D5B5970333A83585826C2A985DE5520D9E934389EFB84B52D344FB21AA8EA38A4940C8332692B8D4DA2393549212EAFDC0F11CA5C9CCA17BA971755E9274F3D74F51C9ED17408FD0BE1C7ADCBE70D6A90C181A0CCD3C04BB4E3A66974B1259061C779C9C4AC6D645BE54AEC11BA47A9D9E59373FE5B33BEE7995E5B10E6FA02ED928CC41987CC55AF84BBEE9ECA01D5D35DA7F6C1249FC2511CC7B5660DDE235BB77F9C79C38C531418A40A53DD")
// console.log("解签密函数测试：");
// console.log(unsign_result.flag_unsigncrytion);
// console.log(unsign_result.flag_replay_attack);
// console.log(unsign_result.flag_tamper_attack);
// console.log(unsign_result.plaintext);
// console.log(unsign_result.timestamp);
// console.log(unsign_result.time_unsigncrytion);

// //截获函数
// var intercept_result = sm2.intercept_cipher("hahaha")
// console.log("截获函数：")
// console.log(intercept_result.flag_intercept);
// console.log(intercept_result.intercepted_ciphertext);

// //截获函数
// var tamper_result = sm2.tamper_attack("lueluelue")
// console.log("篡改攻击：")
// console.log(tamper_result.flag_do_tamper);
// console.log(tamper_result.ciphertext_new);

// //截获函数
// var replay_result = sm2.replay_attack("yingyingying")
// console.log("重放攻击：")
// console.log(replay_result.flag_do_replay);
// console.log(replay_result.ciphertext_unsigncrytion);


