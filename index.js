// 用来表示message不同的生命周期

var message = {
    a_unsign_message:"",
    a_sign_message:"",
    b_sign_message:"",
    b_unsign_message:"",
    c_sign_message:"",
    c_tamper_message:"",
    d_sign_message:"",
    d_replay_message:"",
    send_message:"",
    receive_message:""
}



sm2 = require('./build/Release/sm2');
/*
* 1. 完成基本的逻辑功能
* 2. 完成输入输出的检测
* 3. 完成错误处理
* 4. 打包发布。
*/
$(document).ready(function(){
    $('#a_gen_key').click(function(){
        // $('#modal').modal('show');
        private_key = $('#a_private_key').val();
        // console.log(private_key)
        result = sm2.generate_A(private_key);
        // console.log(public_key.public_A)
        $('#a_public_key').val(result.public_A);
        return;
    })

    $('#a_encrypt').click(function(){
        // 设置message生命周期
        message.a_unsign_message = $('#a_unsign_message').val();
        var result = sm2.signcryption(message.a_unsign_message);
        message.a_sign_message = result.ciphertext;

        //显示
        $('#a_sign_message').val(result.ciphertext);
        if(result.flag_signcrytion==1){
            $('#a_sign_flag').attr('checked','');
            // console.log(1111)
        }
        else{
            $('#a_sign_flag').removeAttr('checked');
            console.log(222)
        }
        $('#a_sign_time').text(result.time_signcrytion);
        return;
    })

    $('#a_send').click(function(){
        message.send_message = message.a_sign_message;
    })

    $('#b_gen_key').click(function(){
        private_key = $('#b_private_key').val();
        result = sm2.generate_B(private_key);
        $('#b_public_key').val(result.public_B);
    })

    $('#b_receive').click(function(){
        message.receive_message=message.send_message;
        $('#b_sign_message').val(message.receive_message);
    })

    $('#b_unsign').click(function(){
        message.b_sign_message = message.receive_message;
        var result = sm2.unsigncryption(message.b_sign_message );
        message.b_unsign_message = result.plaintext;

        if(result.flag_unsigncrytion==1){
            $('#b_is_unsign').attr('checked','');
            $('#b_unsign_message').val(message.b_unsign_message);
            $('#b_unsign_time').text(result.time_unsigncrytion);
            $('#b_unsign_timestamp').text(result.timestamp)
        }
        else{
            $('#b_is_unsign').removeAttr('checked');
        }

        if(result.flag_tamper_attack==1){
            $('#b_is_tamper').attr('checked','');
            $('#b_unsign_message').val('failed ,tamper');

        }
        else{
            $('#b_is_tamper').removeAttr('checked');
        }

        if(result.flag_replay_attack==1){
            $('#b_is_replay').attr('checked','');
            $('#b_unsign_message').val('failed ,replay');

        }
        else{
            $('#b_is_replay').removeAttr('checked');

        }

        return;
    })

    $('#c_intercept').click(function(){
        message.c_sign_message=message.send_message;
        var result = sm2.intercept_cipher(message.send_message);
        if(result.flag_intercept==1){
            $('#c_sign_message').val(message.c_sign_message);
        }
        else{
            $('#c_sign_message').val('failed to intercept')
        }

        return;
    })

    $('#c_tamper').click(function(){
        var result = sm2.tamper_attack(message.c_sign_message);
        if(result.flag_do_tamper==1){
            $('#c_tamper_message').val(result.ciphertext_new);
        }
        else{
            $('#c_tamper_message').val('failed to tamper');
        }
        message.tamper_message = result.ciphertext_new;
        return ;
    })

    $('#c_send').click(function(){
        message.send_message = message.tamper_message;
        return ;
    })

    $('#d_intercept').click(function(){
        message.d_sign_message=message.send_message;
        var result = sm2.intercept_cipher(message.send_message);
        if(result.flag_intercept==1){
            $('#d_sign_message').val(message.d_sign_message);
        }
        else{
            $('#d_sign_message').val('failed to intercept')
        }

        return;

    })

    $('#d_send').click(function(){
        var result = sm2.replay_attack(message.d_sign_message);
        if(result.flag_do_replay==1){
            $('#d_replay_message').val(result.ciphertext_unsigncrytion);
        }
        else{
            $('#d_replay_message').val('failed to intercept');
        }
        message.replay_message = result.ciphertext_unsigncrytion;
        message.send_message = message.replay_message;
        return ;
    })

})




// document.getElementById("a_gen_key").onclick=function(){
//     //弹出框能工作了
//     $('#modal').modal('show');
    
//     return;
// }

// var message=""
// var encrypt_message=""
// var send_message=""
// var intercept_message1=""
// var tamper_message=""
// var intercept_message2=""
// var replay_message=""
// var receive_message=""
// var unsgin_message=""
// document.getElementById("encrypt").onclick=function (){

//     message = document.getElementById("message").value;
//     var sign_result = sm2.signcryption(message);
//     encrypt_message = sign_result.ciphertext;
//     document.getElementById("sign_message").innerHTML=sign_result.ciphertext;
//     document.getElementById("sign_time").innerHTML=sign_result.time_signcrytion;
//     document.getElementById("sign_flag").innerHTML=sign_result.flag_signcrytion;
//     return;
// }

// document.getElementById("send").onclick=function(){
//     send_message = encrypt_message;
//     return;
// }

// document.getElementById("receive").onclick=function (){
//     alert(send_message)
//     receive_message=send_message;
//     document.getElementById("receive_message").innerHTML=receive_message;
//     return;
// }

// document.getElementById("unsign").onclick=function (){
//     var unsign_result = sm2.unsigncryption(receive_message);
//     unsgin_message=unsign_result.plaintext;
//     document.getElementById("unsign_message").innerHTML=unsign_result.plaintext;
//     document.getElementById("unsign_is_tamper").innerHTML=unsign_result.flag_tamper_attack;
//     document.getElementById("unsign_is_replay").innerHTML=unsign_result.flag_replay_attack;
//     document.getElementById("unsign_is_unsign").innerHTML=unsign_result.flag_unsigncrytion;
//     document.getElementById("unsign_time").innerHTML=unsign_result.time_unsigncrytion;
//     document.getElementById("unsign_timestamp").innerHTML=unsign_result.timestamp;
//     return;
// }

// document.getElementById("intercept1").onclick=function(){
//     var intercept_result = sm2.intercept_cipher(send_message)
//     intercept_result.flag_intercept;
//     intercept_message1=intercept_result.intercepted_ciphertext;
//     document.getElementById("intercept_message1").innerHTML=intercept_message1;
//     return;
// }

// document.getElementById("send1").onclick=function(){
//     var tamper_result = sm2.tamper_attack(intercept_message1);
//     // tamper_result.flag_do_tamper;
//     tamper_message = tamper_result.ciphertext_new;
//     document.getElementById("tamper_message").innerHTML=tamper_message;
//     send_message=tamper_message;
//     alert(send_message)
//     return;
// }

// document.getElementById("intercept2").onclick=function(){
//     var intercept_result = sm2.intercept_cipher(send_message)
//     intercept_result.flag_intercept;
//     intercept_message2=intercept_result.intercepted_ciphertext;
//     document.getElementById("intercept_message2").innerHTML=intercept_message2;
//     return;
// }


// document.getElementById("send2").onclick=function(){
//     var replay_result = sm2.replay_attack(intercept_message2)
//     replay_result.flag_do_replay;
//     replay_message = replay_result.ciphertext_unsigncrytion;
//     document.getElementById("replay_message").innerHTML=replay_message;
//     send_message=replay_message;
//     return;
// }

