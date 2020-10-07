// 用来表示message不同的生命周期
var message=""
var encrypt_message=""
var send_message=""
var intercept_message1=""
var tamper_message=""
var intercept_message2=""
var replay_message=""
var receive_message=""
var unsgin_message=""


sm2 = require('./build/Release/sm2');

$(document).ready(function(){
    $("#a_gen_key").click(function(){
        // $('#modal').modal('show');
        private_key = $('#a_private_key').text();
        console.log(private_key)
        public_key = sm2.generate_A(private_key);
        console.log(public_key.public_A)
        $('#a_public_key').text(public_key.public_A);
        return;
    })

    $("#a_encrypt").click(function(){
        $('#modal').modal('show');
        return;
    })

})


// document.getElementById("a_gen_key").onclick=function(){
//     //弹出框能工作了
//     $('#modal').modal('show');
    
//     return;
// }
document.getElementById("encrypt").onclick=function (){

    message = document.getElementById("message").value;
    var sign_result = sm2.signcryption(message);
    encrypt_message = sign_result.ciphertext;
    document.getElementById("sign_message").innerHTML=sign_result.ciphertext;
    document.getElementById("sign_time").innerHTML=sign_result.time_signcrytion;
    document.getElementById("sign_flag").innerHTML=sign_result.flag_signcrytion;
    return;
}

document.getElementById("send").onclick=function(){
    send_message = encrypt_message;
    return;
}

document.getElementById("receive").onclick=function (){
    alert(send_message)
    receive_message=send_message;
    document.getElementById("receive_message").innerHTML=receive_message;
    return;
}

document.getElementById("unsign").onclick=function (){
    var unsign_result = sm2.unsigncryption(receive_message);
    unsgin_message=unsign_result.plaintext;
    document.getElementById("unsign_message").innerHTML=unsign_result.plaintext;
    document.getElementById("unsign_is_tamper").innerHTML=unsign_result.flag_tamper_attack;
    document.getElementById("unsign_is_replay").innerHTML=unsign_result.flag_replay_attack;
    document.getElementById("unsign_is_unsign").innerHTML=unsign_result.flag_unsigncrytion;
    document.getElementById("unsign_time").innerHTML=unsign_result.time_unsigncrytion;
    document.getElementById("unsign_timestamp").innerHTML=unsign_result.timestamp;
    return;
}

document.getElementById("intercept1").onclick=function(){
    var intercept_result = sm2.intercept_cipher(send_message)
    intercept_result.flag_intercept;
    intercept_message1=intercept_result.intercepted_ciphertext;
    document.getElementById("intercept_message1").innerHTML=intercept_message1;
    return;
}

document.getElementById("send1").onclick=function(){
    var tamper_result = sm2.tamper_attack(intercept_message1);
    // tamper_result.flag_do_tamper;
    tamper_message = tamper_result.ciphertext_new;
    document.getElementById("tamper_message").innerHTML=tamper_message;
    send_message=tamper_message;
    alert(send_message)
    return;
}

document.getElementById("intercept2").onclick=function(){
    var intercept_result = sm2.intercept_cipher(send_message)
    intercept_result.flag_intercept;
    intercept_message2=intercept_result.intercepted_ciphertext;
    document.getElementById("intercept_message2").innerHTML=intercept_message2;
    return;
}


document.getElementById("send2").onclick=function(){
    var replay_result = sm2.replay_attack(intercept_message2)
    replay_result.flag_do_replay;
    replay_message = replay_result.ciphertext_unsigncrytion;
    document.getElementById("replay_message").innerHTML=replay_message;
    send_message=replay_message;
    return;
}

