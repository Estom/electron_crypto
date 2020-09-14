// hello.js
const sm2 = require('./build/Release/sm2');

var test = sm2.test("abcde");

console.log(test.part0.msg_len);
console.log(test.part0.encryp_msg_len);
console.log(test.part0.encryp_mes_len_rs);
console.log(test.part0.encryp_msg);

console.log(test.part1.times);
console.log(test.part1.dur);
console.log(test.part1.total_bytes);
console.log(test.part1.process_time);
console.log(test.part1.per_process_time);

console.log(test.part2.times);
console.log(test.part2.dur);
console.log(test.part2.total_bytes);
console.log(test.part2.process_time);
console.log(test.part2.per_process_time);

console.log(test.part3.times);
console.log(test.part3.dur);
console.log(test.part3.total_bytes);
console.log(test.part3.process_time);
console.log(test.part3.per_process_time);