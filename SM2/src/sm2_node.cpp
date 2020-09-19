// hello.cc using N-API
#include <node_api.h>
#include <assert.h>
#include <time.h>
#include <stdio.h>
#include "sm2.h"
#include "part1.h"
#include "part2.h"
#include "part3.h"
#include "part4.h"
#include "part5.h"
//定义接口函数
napi_value hello_method(napi_env env, napi_callback_info info) {
  napi_status status;
  size_t argc = 1;
  napi_value args[1];
  status = napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
  assert(status == napi_ok);


  napi_value obj;
  status = napi_create_object(env, &obj);
  assert(status == napi_ok);

  status = napi_set_named_property(env, obj, "msg", args[0]);
  assert(status == napi_ok);

  // status = napi_create_string_utf8(env, "world", NAPI_AUTO_LENGTH, &greeting);
  return obj;
}

//定义接口函数
napi_value test_method(napi_env env, const napi_callback_info info){
  napi_value result;
  napi_status status;
  
  //创建返回对象
  status= napi_create_object(env,&result);
  assert(status == napi_ok);

  //获得1个参数messge
  size_t argc = 1;
  napi_value args[1];
  status = napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
  assert(status == napi_ok);
  if (argc < 1) {
    napi_throw_type_error(env, nullptr, "Wrong number of arguments");
    return nullptr;
  }

  //数值类型测试 是可以的，说明传递参数没有问题。关键是取不出字符串。
  // double value1;
  // status = napi_get_value_double(env, args[0], &value1);
  // printf("hel%lf",value1);

  //对buff的测试
  // napi_value buff;
  // void* ttt;
  // status = napi_create_buffer(env,5,&ttt,&buff);
  // napi_value n_message = args[0];
  // status = napi_set_named_property(env, result, "msg", args[0]);
  // assert(status == napi_ok);

  
  //将message转换为C类型的数据，并存储到全局变量message当中
  size_t length=0;
  status = napi_get_value_string_utf8(env,args[0],NULL,0,&length);
  assert(status == napi_ok);
  printf("string length:%d\n",length);

  char* buff=(char*)malloc(255);
  status = napi_get_value_string_utf8(env,args[0],buff,length+1,&length);
  assert(status == napi_ok);
  buff[length]='\0';

  message = buff;
  printf("meesage:%s\n",message);

  //free(buff);



  const int TIMES = 1000;
	clock_t start, end;
	double dur;
	int total_bytes;

  // message_st message_data;

	start = clock();
  // int with_r_s_length;
	for (int i = 0; i < TIMES; i++) {
     test_part5(sm2_param_recommand, TYPE_GFp, 256);
	}
	end = clock();
	dur = (double)(end - start) / CLOCKS_PER_SEC;
	total_bytes = strlen((char *)message) * TIMES;

  // int len = strlen((char *)message_data.C);
  napi_value msg_len,encryp_msg_len,encryp_mes_len_rs,encryp_msg;
  status = napi_create_int32(env,10,&msg_len);
  status = napi_create_int32(env,100,&encryp_msg_len);
  status = napi_create_int32(env,1000,&encryp_mes_len_rs);
  status = napi_create_string_utf8(env,"woshihaore", 10, &encryp_msg);
  assert(status == napi_ok);
  // status = napi_create_int32(env,strlen((char *)message_data.message),&msg_len);
  // status = napi_create_int32(env,len,&encryp_msg_len);
  // status = napi_create_int32(env,with_r_s_length,&encryp_mes_len_rs);
  // status = napi_create_string_utf8(env,(char*)(message_data.C), len, &encryp_msg);
  // assert(status == napi_ok);

  // 将C类型的数据转换为napi的数据并放到napi的对象当中
  napi_value part0;
  status= napi_create_object(env,&part0);
  assert(status == napi_ok);

  // 放到part0对象当中
  status = napi_set_named_property(env,part0, "msg_len", msg_len);
  assert(status == napi_ok);
  status = napi_set_named_property(env,part0, "encryp_msg_len", encryp_msg_len);
  assert(status == napi_ok);
  status = napi_set_named_property(env,part0, "encryp_mes_len_rs", encryp_mes_len_rs);
  assert(status == napi_ok);
  status = napi_set_named_property(env,part0, "encryp_msg", encryp_msg);
  assert(status == napi_ok);
  // 加入到结果
  status = napi_set_named_property(env,result, "part0", part0);
  assert(status == napi_ok);

  //将C类型的数据转换为napi的数据并放到napi的对象当中
  napi_value part1;
  status= napi_create_object(env,&part1);
  assert(status == napi_ok);

  //转换为napi数据类型
  napi_value n_times,n_dur,n_total_bytes,n_process_time,n_per_process_time;
  status = napi_create_int32(env,TIMES,&n_times);
  assert(status == napi_ok);
  status = napi_create_double(env,dur,&n_dur);
  assert(status == napi_ok);
  status = napi_create_int32(env,total_bytes,&n_total_bytes);
  assert(status == napi_ok);
  status = napi_create_double(env,TIMES / (dur * 1000),&n_process_time);
  assert(status == napi_ok);
  status = napi_create_double(env,total_bytes / dur,&n_per_process_time);
  assert(status == napi_ok);

  //放到part1对象当中
  status = napi_set_named_property(env,part1, "times", n_times);
  assert(status == napi_ok);
  status = napi_set_named_property(env,part1, "dur", n_dur);
  assert(status == napi_ok);
  status = napi_set_named_property(env,part1, "total_bytes", n_total_bytes);
  assert(status == napi_ok);
  status = napi_set_named_property(env,part1, "process_time", n_process_time);
  assert(status == napi_ok);
  status = napi_set_named_property(env,part1, "per_process_time", n_per_process_time);
  assert(status == napi_ok);
  //加入到结果
  status = napi_set_named_property(env,result, "part1", part1);
  assert(status == napi_ok);

  //////////////////////////////////////////////////////
	start = clock();
	for (int i = 0; i < TIMES; i++) {
		test_part5_enc_sig(sm2_param_recommand, TYPE_GFp, 256);
	}
	end = clock();
	dur = (double)(end - start) / CLOCKS_PER_SEC;
	total_bytes = strlen((char *)message) * TIMES;

  //将C类型的数据转换为napi的数据并放到napi的对象当中
  napi_value part2;
  status = napi_create_object(env,&part2);
  assert(status == napi_ok);
  

  //转换为napi数据类型
  // napi_value n_times,n_dur,n_total_bytes,n_process_time,n_per_process_time;
  status = napi_create_int32(env,TIMES,&n_times);
  assert(status == napi_ok);
  status = napi_create_double(env,dur,&n_dur);
  assert(status == napi_ok);
  status = napi_create_int32(env,total_bytes,&n_total_bytes);
  assert(status == napi_ok);
  status = napi_create_double(env,TIMES / (dur * 1000),&n_process_time);
  assert(status == napi_ok);
  status = napi_create_double(env,total_bytes / dur,&n_per_process_time);
  assert(status == napi_ok);

  //放到part2对象当中
  status = napi_set_named_property(env,part2, "times", n_times);
  assert(status == napi_ok);
  status = napi_set_named_property(env,part2, "dur", n_dur);
  assert(status == napi_ok);
  status = napi_set_named_property(env,part2, "total_bytes", n_total_bytes);
  assert(status == napi_ok);
  status = napi_set_named_property(env,part2, "process_time", n_process_time);
  assert(status == napi_ok);
  status = napi_set_named_property(env,part2, "per_process_time", n_per_process_time);
  assert(status == napi_ok);
  //加入到结果当中
  status = napi_set_named_property(env,result, "part2", part2);
  assert(status == napi_ok);

  //////////////////////////////////////////////////////
	start = clock();
	for (int i = 0; i < TIMES; i++) {
		test_part5_ver_dec(sm2_param_recommand, TYPE_GFp, 256);
	}
	end = clock();
	dur = (double)(end - start) / CLOCKS_PER_SEC;
	total_bytes = strlen((char *)message) * TIMES;

  //将C类型的数据转换为napi的数据并放到napi的对象当中
  napi_value part3;
  status = napi_create_object(env,&part3);
  assert(status == napi_ok);
  
  //转换为napi数据类型
  // napi_value n_times,n_dur,n_total_bytes,n_process_time,n_per_process_time;
  status = napi_create_int32(env,TIMES,&n_times);
  assert(status == napi_ok);
  status = napi_create_double(env,dur,&n_dur);
  assert(status == napi_ok);
  status = napi_create_int32(env,total_bytes,&n_total_bytes);
  assert(status == napi_ok);
  status = napi_create_double(env,TIMES / (dur * 1000),&n_process_time);
  assert(status == napi_ok);
  status = napi_create_double(env,total_bytes / dur,&n_per_process_time);
  assert(status == napi_ok);

  //放到par1对象当中
  status = napi_set_named_property(env,part3, "times", n_times);
  assert(status == napi_ok);
  status = napi_set_named_property(env,part3, "dur", n_dur);
  assert(status == napi_ok);
  status = napi_set_named_property(env,part3, "total_bytes", n_total_bytes);
  assert(status == napi_ok);
  status = napi_set_named_property(env,part3, "process_time", n_process_time);
  assert(status == napi_ok);
  status = napi_set_named_property(env,part3, "per_process_time", n_per_process_time);
  assert(status == napi_ok);

  //放到result当中
  status = napi_set_named_property(env,result, "part3", part3);
  assert(status == napi_ok);

  free(buff);
  return result;
}

// napi_value init(napi_env env, napi_value exports) {
//   napi_status status;
//   // napi_value new_exports;
//   napi_value fn_test_method;
//   napi_value fn_hello_method;

//   //创建了一个NAPI方法，然后直接返回这个方法。那么这个模块本身也就对应这个方法
//   status = napi_create_function(env, nullptr, NAPI_AUTO_LENGTH, test_method, nullptr, &fn_test_method);
//   assert(status == napi_ok);
//   status = napi_set_named_property(env,exports, "test", fn_test_method);
//   assert(status == napi_ok);

//   //在exports暴露的接口中，绑定其他的方法。模块的hello属性，是一个方法。
//   status = napi_create_function(env, nullptr, NAPI_AUTO_LENGTH, hello_method, nullptr, &fn_hello_method);
//   assert(status == napi_ok);
//   status = napi_set_named_property(env, exports, "hello", fn_hello_method);
//   assert(status == napi_ok);
//   return exports;
// }

// NAPI_MODULE(NODE_GYP_MODULE_NAME, init)
