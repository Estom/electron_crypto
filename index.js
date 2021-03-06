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
    dis_none();

    $('#init_server').click(function(){
        result = sm2.init_server()
        $("#server_bar").attr("style","width:100%")
        // $('#modal').modal('show');
        dis_all();
    })

    $('#a_gen_key').click(function(){
        // $('#modal').modal('show');
        private_key = $('#a_private_key').val();
        // console.log(private_key)
        result = sm2.generate_A(private_key);
        // console.log(public_key.public_A)
        $('#a_public_key').val(result.public_A);
        dis_none();
        dis_interface_a();
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
            $('#a_sign_flag').text('是');
            // console.log(1111)
        }
        else{
            $('#a_sign_flag').text('否');
            console.log(222)
        }
        $('#a_sign_time').text(result.time_signcrytion);
        dis_none();
        dis_interface_a();
        return;
    })

    $('#a_send').click(function(){
        message.send_message = message.a_sign_message;
        sm2.send_signal_A();
        dis_none();
        dis_interface_a();
        dis_a_b();
        return;
    })

    $('#b_gen_key').click(function(){
        private_key = $('#b_private_key').val();
        result = sm2.generate_B(private_key);
        $('#b_public_key').val(result.public_B);
        dis_none();
        dis_interface_b();
        return;
    })

    $('#b_receive').click(function(){
        message.receive_message=message.send_message;
        var receive_result = sm2.receive_signal_B();
        message.receive_message=receive_result.ciphertext_B;
        $('#b_sign_message').val(message.receive_message);
        dis_none();
        dis_interface_b();
        return;
    })

    $('#b_unsign').click(function(){
        message.b_sign_message = message.receive_message;
        var result = sm2.unsigncryption(message.b_sign_message );
        message.b_unsign_message = result.plaintext;

        if(result.flag_unsigncrytion==1){
            $('#b_is_unsign').text('是');
            $('#b_unsign_message').val(message.b_unsign_message);
            $('#b_unsign_time').text(result.time_unsigncrytion);
            $('#b_unsign_timestamp').text(result.timestamp)
        }
        else{
            $('#b_is_unsign').text('否');
            $('#b_unsign_time').text('');
            $('#b_unsign_timestamp').text('')
        }

        if(result.flag_tamper_attack==1){
            $('#b_is_tamper').text('是');
            $('#b_unsign_message').val('failed ,tamper');

        }
        else{
            $('#b_is_tamper').text('否');
        }

        if(result.flag_replay_attack==1){
            $('#b_is_replay').text('是');
            $('#b_unsign_message').val('failed ,replay');

        }
        else{
            $('#b_is_replay').text('否');

        }
        dis_none();
        dis_interface_b();
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
        dis_none();
        dis_interface_attacker();
        dis_a_attacker();
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
        dis_none();
        dis_interface_attacker();
        dis_attacker_b();
        return ;
    })

    // $('#c_send').click(function(){
    //     message.send_message = message.tamper_message;
    //     return ;
    // })

    // $('#d_intercept').click(function(){
    //     message.d_sign_message=message.send_message;
    //     var result = sm2.intercept_cipher(message.send_message);
    //     if(result.flag_intercept==1){
    //         $('#d_sign_message').val(message.d_sign_message);
    //     }
    //     else{
    //         $('#d_sign_message').val('failed to intercept')
    //     }
    //     dis_none();
    //     dis_interface_attacker();
    //     dis_a_attacker();
    //     return;

    // })

    $('#c_replay').click(function(){
        var result = sm2.replay_attack(message.d_sign_message);
        if(result.flag_do_replay==1){
            $('#d_replay_message').val(result.ciphertext_unsigncrytion);
        }
        else{
            $('#d_replay_message').val('failed to intercept');
        }
        message.replay_message = result.ciphertext_unsigncrytion;
        message.send_message = message.replay_message;
        dis_none();
        dis_interface_attacker();
        dis_attacker_b();
        return ;
    })
})

// 可以在在下边制作一组动画函数。
// 使用HTML规范位置
// 使用CSS3画图
// 使用jQuery实现动画效果函数，然后在执行通信过程中，对通信过程进行动态展示

function dis_none(){
    $('#ib').hide();
    $('#bi').hide();
    $('#ia').hide();
    $('#ai').hide();
    $('#it').hide();
    $('#ti').hide();
    $('#ab').hide();
    $('#ba').hide();
    $('#at').hide();
    $('#tb').hide();
}
function dis_all(){
    $('#ib').fadeIn("slow");
    $('#bi').fadeIn("slow");
    $('#ia').fadeIn("slow");
    $('#ai').fadeIn("slow");
    $('#it').fadeIn("slow");
    $('#ti').fadeIn("slow");
    $('#ab').fadeIn("slow");
    $('#ba').fadeIn("slow");
    $('#at').fadeIn("slow");
    $('#tb').fadeIn("slow");
}
function dis_interface_a(){
    $('#ia').fadeIn("slow");
    $('#ia').children().css("stroke","red");
    $('#ai').fadeIn("slow");
    $('#ai').children().css("stroke","red");

}
function dis_interface_b(){
    $('#ib').fadeIn("slow");
    $('#ib').children().css("stroke","red");
    $('#bi').fadeIn("slow");
    $('#bi').children().css("stroke","red");
}
function dis_interface_attacker(){
    $('#it').fadeIn("slow");
    $('#it').children().css("stroke","red");
    $('#ti').fadeIn("slow");
    $('#ti').children().css("stroke","red");
}
function dis_a_b(){
    $('#ab').fadeIn("slow");
    $('#ab').children().css("stroke","red");
    $('#ba').fadeIn("slow");
    $('#ba').children().css("stroke","red");
}
function dis_a_attacker(){
    $('#at').fadeIn("slow");
    $('#at').children().css("stroke","red");
}
function dis_attacker_b(){
    $('#tb').fadeIn("slow");
    $('#tb').children().css("stroke","red");
}


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

