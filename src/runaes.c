#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <math.h>
#include "aes_rp.h"
#include "aes_rp_prg.h"
#include "share.h"
#include "aes_share.h"
#include "common.h"
#include "prg.h"
#include "cvector.h"
#include "time.h"
#include "difftribute_table.h"
#include "filter.h"
#include "verify.h"
#include "recovery.h"
#include "print.h"
#include "repeat_attack.h"
#include "encrypt.h"

int random_in_key(byte in[16],byte out[16],byte key[16],byte outex[16],int nt,byte w[176]){
	//随机注入错误
	srand((unsigned)time(NULL) + rand());
	byte loc;
	byte value;
	byte rel_value;
	do{
		loc= 0 + rand() % (256 - 0); 
		value = 1 + rand() % (256 - 1);
		rel_value = get_taffineValue(loc);
		set_taffineValue(loc, value);
	}while(rel_value==value);
	printf("注入错误的位置是%02x,错误值是%02x,原值是%02x\n",loc,value,taffine_copy[loc]);
	FILE *fpWrite = fopen("experiment.txt", "a+");
	fprintf(fpWrite,"注入错误的位置是%02x,错误值是%02x,原值是%02x\n",loc,value,taffine_copy[loc]);
	fclose(fpWrite);
	if(value == rel_value){
		return -1;
	}
	//模拟每次攻击使用随机明文
	for (int i = 0; i < 16; i++) {
		in[i] = 0 + rand() % (256 - 0);
	}
	printf("\n随机明文是\n");
	fpWrite = fopen("experiment.txt", "a+");
	fprintf(fpWrite,"\n随机明文是\n");
	fclose(fpWrite);
	print_4_by_4(in);
	//模拟每次攻击使用随机主密钥
	for (int i = 0; i < 16; i++) {
		key[i] = 0 + rand() % (256 - 0);
	}
	printf("\n随机密钥是：\n");
	fpWrite = fopen("experiment.txt", "a+");
	fprintf(fpWrite,"\n随机密钥是：\n");
	fclose(fpWrite);
	print_4_by_4(key);
	printf("\n子密钥是：\n");
	fpWrite = fopen("experiment.txt", "a+");
	fprintf(fpWrite,"\n子密钥是：\n");
	fclose(fpWrite);
	run_aes(&aes,in,out,key,outex,nt,0,w);//输出密钥用
	printf("\n子密钥结束\n\n");
	fpWrite = fopen("experiment.txt", "a+");
	fprintf(fpWrite,"\n子密钥结束\n\n");
	fclose(fpWrite);
	return 0;
}

int main(){
	clock_t start,middle1,middle2,finish;
   	double duration;
	start = clock();
  	int n = Share_num;//share的个数
	int base = 1;
  	int nt = 10;
	diff_table();
	int all_encrypt_num[Experment_num] ;
	int first_encrypt_num[Experment_num];
	int later_fail_encrypt_num[attack_round][Experment_num];//0没有用到，从1开始用的
	int later_out_time_encrypt_num[attack_round][Experment_num] ;//0没有用到，从1开始用的
	for(int exp=0;exp<Experment_num;exp++){
		all_encrypt_num[exp] = 0;
		first_encrypt_num[exp] = 0;
	}
	for(int i=0;i<attack_round;i++){
		for(int j=0;j<Experment_num;j++){
			later_fail_encrypt_num[i][j] = 0;
			later_out_time_encrypt_num[i][j] = 0;
		}
	}
	double excute_time[Experment_num];//每次实验的执行时间，先不统计，因为现在还涉及读写文件，会消耗大量时间

	int first_success_num = 0;//成功的次数
	int first_fail_num = 0;//失败的次数
	int first_timeout_num = 0;//超时的次数

	int other_fail_num = 0;//其他未知的失败次数
	int appear_4_but_not_match = 0;//
	int no_chain_num = 0;//找不到链的情况（继续找的情况）
	int more_chain_num = 0;//匹配多条链的情况
	int one_chain_num = 0;//刚好匹配四条链的情况
	int invalid_error_num = 0;//注入无效错误的情况
	
	int success_num_in_fail[attack_round] = {0};
	int success_num_in_timeout[attack_round] = {0};
	int fail_num_in_fail[attack_round] = {0};
	int fail_num_in_timeout[attack_round] = {0};
	int timeout_num_in_fail[attack_round] = {0};
	int timeout_num_in_timeout[attack_round] = {0};

	int success_num_if_timeout = 0;//超过设定的复杂度，但是攻击成功了
	int fail_num_if_timeout = 0;//超过设定的复杂度，但是攻击失败
	int timeout_num_if_timeout = 0;//超过设定的复杂度，真的超时了
	FILE *fpWrite ;
	printf("使用的掩码方案为\n");
	fpWrite = fopen("experiment.txt", "a+");
	fprintf(fpWrite,"使用的掩码方案为\n");
	if(is_rp10){
		printf("is_rp10\n");
		fprintf(fpWrite,"is_rp10\n");
	}
	else if(is_rp10_flr){
		printf("is_rp10_flr\n");
		fprintf(fpWrite,"is_rp10_flr\n");
	}
	else if(is_rp10_ilr){
		printf("is_rp10_ilr\n");
		fprintf(fpWrite,"is_rp10_ilr\n");
	}
	else if(is_rp10_ilr2){
		printf("is_rp10_ilr2\n");
		fprintf(fpWrite,"is_rp10_ilr2\n");
	}
	fclose(fpWrite);

	for(int e=0;e<Experment_num;e++){
		middle1 = clock();
		
		if(Is_print){
			fpWrite= fopen("encrypt_state.txt", "a+");
			fprintf(fpWrite,"第%d次实验：\n",e);
			fclose(fpWrite);
		}
		printf("\n********************************\n第%d次实验\n",e);
		fpWrite = fopen("experiment.txt", "a+");
		fprintf(fpWrite,"\n********************************\n第%d次实验\n",e);
		fclose(fpWrite);
		byte outex[16]={0x39,0x25,0x84,0x1d,0x02,0xdc,0x09,0xfb,0xdc,0x11,0x85,0x97,0x19,0x6a,0x0b,0x32};//预测输出,已经被注释掉了，没用了
		byte in[16]={0x53,0x50,0x7d,0x35,
					0x53,0x71,0x68,0x97,
					0x31,0x03,0xf2,0x6a,
					0x04,0x3b,0x56,0x53};
		byte key[16]={0xd7,0x82,0x0c,0x13,
					0x95,0x97,0x87,0x61,
					0xfc,0x3f,0x52,0xb2,
					0xcc,0xd7,0x94,0xe8};
		byte out[16];
		byte w[176];//扩展密钥
		bool is_random = Is_random;//控制是否随机明文、密钥和错误,调试用 1:表示随机 0:表示固定
		int invalid_error = 0;//判断是否注入了一个无效的错误
		if(is_random == 0){//如果不随机产生明文、密钥和错误
			byte loc = 0xd9; //注入错误的位置
			byte value = 0x25; //注入错误的值
			byte rel_value = get_taffineValue(loc);
			set_taffineValue(loc, value);
			fpWrite = fopen("experiment.txt", "a+");
			printf("注入错误的位置是%02x,错误值是%02x,原值是%02x\n",loc,value,taffine_copy[loc]);
			fprintf(fpWrite,"注入错误的位置是%02x,错误值是%02x,原值是%02x\n",loc,value,taffine_copy[loc]);
			printf("明文是：\n");
			fprintf(fpWrite,"明文是：\n");
			for(int i=0;i<16;i++){
				printf("%02x,",in[i]);
				fprintf(fpWrite,"%02x,",in[i]);
				if((i+1)%4==0){
					printf("\n");
					fprintf(fpWrite,"\n");
				}
			}
			printf("\n密钥是：\n");
			fprintf(fpWrite,"密钥是：\n");
			for(int i=0;i<16;i++){
				printf("%02x,",key[i]);
				fprintf(fpWrite,"%02x,",key[i]);
				if((i+1)%4==0){
					printf("\n");
					fprintf(fpWrite,"\n");
				}
			}
			fclose(fpWrite);
			test_key(in,out,key,outex,n,nt,base,w); //输出扩展密钥用
		}
		else if(is_random == 1){//如果随机产生明文、密钥和错误
			invalid_error = random_in_key(in,out,key,outex,nt,w);
		}
		if(invalid_error == -1){//如果注入了一个无效错误
			all_encrypt_num[e] = 0;
			invalid_error_num++;
			continue;
		}
		byte delta = 0;
		byte differential_cipher_4_error[4][4]={0};
		struct Different_Cipher dc[4];
		int relationship_delta_difference_cipher[4][4] = {{-1,-1,-1,-1},{-1,-1,-1,-1},{-1,-1,-1,-1},{-1,-1,-1,-1}};//记录一组差分值对应第几组delta
		int diff_delta_count[4]={0,0,0,0};//记录一组差分值能够匹配几组delta
		byte cipher_verify[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};//验证的时候使用
		all_encrypt_num[e] = encrypt_find_different(in,out,key,outex,n,nt,base,&delta,differential_cipher_4_error,dc,
			relationship_delta_difference_cipher,diff_delta_count,&appear_4_but_not_match,&no_chain_num,&more_chain_num,
			&one_chain_num,cipher_verify);
		first_encrypt_num[e] = all_encrypt_num[e];
		fpWrite = fopen("experiment.txt", "a+");
		printf("first_encrypt_num:%d\n\n",all_encrypt_num[e]);
		fprintf(fpWrite,"first_encrypt_num:%d\n\n",all_encrypt_num[e]);
		fclose(fpWrite);
		byte guess_key_10round[16][16]={{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
										{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
										{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
										{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}};
		byte key_10round[16]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};//存放求得的第十轮子密钥
		byte main_key[16]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};//存放求得的初始密钥
		byte delta2 = mult(2 , delta);
		byte delta3 = mult(3 , delta);
		byte arr_delta[4][4] = {{delta2,delta3,delta,delta},{delta,delta2,delta3,delta},
			{delta,delta,delta2,delta3},{delta3,delta,delta,delta2}};
		int re_rk = 0;
		re_rk = recovery_10round_key(delta,differential_cipher_4_error,arr_delta,relationship_delta_difference_cipher,dc,
			guess_key_10round,w,diff_delta_count,&first_success_num,&first_fail_num,cipher_verify,in,n,nt,base,key,
			&first_timeout_num,&other_fail_num,&success_num_if_timeout,&fail_num_if_timeout,&timeout_num_if_timeout);

		if(attack_round>1){
			for(int i=1;i<attack_round;i++){
				if(re_rk == -1){
					re_rk = repeat_attack(in,out,key,outex,n, nt, base, &appear_4_but_not_match,&no_chain_num,&more_chain_num,&one_chain_num,all_encrypt_num,
						later_fail_encrypt_num, w,e,&success_num_in_fail[i],&fail_num_in_fail[i],&timeout_num_in_fail[i],&other_fail_num,&success_num_if_timeout,
						&fail_num_if_timeout,&timeout_num_if_timeout,i);
				}
				else if(re_rk == -3){
					re_rk = repeat_attack(in,out,key,outex,n, nt, base, &appear_4_but_not_match,&no_chain_num,&more_chain_num,&one_chain_num,all_encrypt_num,
						later_out_time_encrypt_num, w,e,&success_num_in_timeout[i],&fail_num_in_timeout[i],&timeout_num_in_timeout[i],&other_fail_num,&success_num_if_timeout,
						&fail_num_if_timeout,&timeout_num_if_timeout,i);
				}
				else if(re_rk == 1){
					break;
				}
			}
		}
		fpWrite = fopen("experiment.txt", "a+");
		printf("second_encrypt_num:%d\n",all_encrypt_num[e]);
		fprintf(fpWrite,"second_encrypt_num:%d\n",all_encrypt_num[e]);
		fclose(fpWrite);
		for(int i=0;i<256;i++){	
			taffine[i] = taffine_copy[i];//恢复仿射变换表
		}
		middle2 = clock();
		excute_time[e] = (double)(middle2 - middle1)/ CLOCKS_PER_SEC;
		fpWrite = fopen("experiment.txt", "a+");

		printf("本次实验执行时间:%f\n",excute_time[e]);
		fprintf(fpWrite,"本次实验执行时间:%f\n",excute_time[e]);
		fclose(fpWrite);
		
		print_count(first_success_num,first_fail_num,first_timeout_num, success_num_in_fail, fail_num_in_fail,
			timeout_num_in_fail, success_num_in_timeout, fail_num_in_timeout,
			timeout_num_in_timeout, other_fail_num, no_chain_num, more_chain_num, one_chain_num, invalid_error_num,
			success_num_if_timeout,fail_num_if_timeout,timeout_num_if_timeout);
	}	
	print_encrypt_num( first_encrypt_num, all_encrypt_num, later_fail_encrypt_num, later_out_time_encrypt_num);
	int sum = 0;
	int max = 0;
	int min = 10000;
	for(int i=0;i<Experment_num;i++){
		sum += all_encrypt_num[i];
		if(all_encrypt_num[i]==0){//将无效错误的情况去掉
			continue;
		}
		if(all_encrypt_num[i]>max)
			max = all_encrypt_num[i];
		if(all_encrypt_num[i]<min)
			min = all_encrypt_num[i];
	}
	fpWrite = fopen("experiment.txt", "a+");
	printf("\n总实验次数:%d\n",Experment_num);
	fprintf(fpWrite,"\n总实验次数:%d\n",Experment_num);
	printf("share个数:%d\n",n);
	fprintf(fpWrite,"share个数:%d\n",n);
	printf("平均需要加密%d次才能找到16个字节。\n最多需要%d次，最少需要%d次。\n",sum/Experment_num,max,min);
	fprintf(fpWrite,"平均需要加密%d次才能找到16个字节。\n最多需要%d次，最少需要%d次。\n",sum/Experment_num,max,min);
	fclose(fpWrite);
	print_count(first_success_num,first_fail_num,first_timeout_num, success_num_in_fail, fail_num_in_fail,
		timeout_num_in_fail, success_num_in_timeout, fail_num_in_timeout,
		timeout_num_in_timeout, other_fail_num, no_chain_num, more_chain_num, one_chain_num, invalid_error_num,
		success_num_if_timeout,fail_num_if_timeout,timeout_num_if_timeout);

	finish = clock(); 
	duration = (double)(finish - start) / CLOCKS_PER_SEC; 
	fpWrite = fopen("experiment.txt", "a+");
	printf("总执行时间：%f seconds\n", duration );
	fprintf(fpWrite,"总执行时间：%f seconds\n", duration );
	fclose(fpWrite); 
	fpWrite = fopen("excute_time.txt","a+");
	printf("每次实验的执行时间:\n");
	fprintf(fpWrite,"每次实验的执行时间:\n");
	for(int i=0;i<Experment_num;i++){
		printf("%fs\n",excute_time[i]);
		fprintf(fpWrite,"%f\n",excute_time[i]);
	}
	printf("\n");
	fprintf(fpWrite,"\n");
	fclose(fpWrite);
	printf("使用的掩码方案为\n");
	fpWrite = fopen("experiment.txt", "a+");
	fprintf(fpWrite,"使用的掩码方案为\n");
	if(is_rp10){
		printf("is_rp10\n");
		fprintf(fpWrite,"is_rp10\n");
	}
	else if(is_rp10_flr){
		printf("is_rp10_flr\n");
		fprintf(fpWrite,"is_rp10_flr\n");
	}
	else if(is_rp10_ilr){
		printf("is_rp10_ilr\n");
		fprintf(fpWrite,"is_rp10_ilr\n");
	}
	else if(is_rp10_ilr2){
		printf("is_rp10_ilr2\n");
		fprintf(fpWrite,"is_rp10_ilr2\n");
	}
	fclose(fpWrite);
	return 0;
}

/*
	byte in[16],out[16];
  	byte key[16];
  	printMes("in:",inex);
  	printMes("key:",keyex);

  	for(i=0;i<16;i++) key[i]=keyex[i];
  	for(i=0;i<16;i++) in[i]=inex[i];
  	int dt,base;
  printf("Without countermeasure, plain: \n");
  base=run_aes(&aes,in,out,key,outex,nt,0);           //运行普通的AES加密算法，返回加密10轮所用的时间，得到时间基准base 

  printf("Without countermeasure, RP: \n");
  run_aes(&aes_rp,in,out,key,outex,nt,base);          //运行AES_rp加密算法（使用有限域乘法+仿射变换代替S盒），得到时间基准base 
  printf("warning！得到时间基准base在mac上等于：%d\n",base); 


  for(n=3;n<=6;n+=1)
  {
    printf("n=%d\n",n);
    printf("With RP countermeasure: ");
    run_aes_share(in,out,key,outex,n,&subbyte_rp_share,nt,base);     //用share技术的AES加密算法 (使用有限域乘法share+仿射变换代替S盒),行移位share,列混合share，轮密钥加share,时间基准base
    
    printf("  With RP countermeasure, with flr: ");
    int rprg=rprg_flr(n);
    run_aes_share_prg(in,out,key,outex,n,&subbyte_rp_share_flr,base,nt,rprg);
    printf(" trand=%d tprgcount=%d\n",rprg*2*n,(480*n+1120)*(n-1));

//    printf("  With RP countermeasure, with ilr: ");
//    rprg=rprg_ilr(n);
//    run_aes_share_prg(in,out,key,outex,n,&subbyte_rp_share_ilr,base,nt,rprg);
//    printf(" trand=%d tprgcount=%d\n",8*n*(n-1)*(n-1),(960*n+160)*(n-1));
//
//    printf("  With RP countermeasure, with ilr2: ");
//    rprg=rprg_ilr(n);
//    run_aes_share_prg(in,out,key,outex,n,&subbyte_rp_share_ilr2,base,nt,rprg);
//    printf(" trand=%d tprgcount=%d\n",8*n*(n-1)*(n-1),(480*n+1120)*(n-1));
//
//    printf("  With RP countermeasure, with flr, multiple prg: ");
//    run_aes_share_mprg(in,out,key,outex,n,&subbyte_rp_share_flr_mprg,TFLR,base,nt);
//    printf(" trand=%d\n",(n*n+9*n-10)*(n-1));
//
//    printf("  With RP countermeasure, with ilr, multiple prg: ");
//    run_aes_share_mprg(in,out,key,outex,n,&subbyte_rp_share_ilr_mprg,TILR,base,nt);
//    printf(" trand=%d\n",(12*n-12)*(n-1));
    if(n<=4)
    {
      printf(" With RP countermeasure, with flr, mprgmat: ");
      run_aes_share_mprgmat(in,out,key,outex,n,base,nt);
      printf(" predicted rand: %d\n",n*(n-1)/2*2*31+3*(n-1)*2*38);
    }
    
    printf("  With randomized table : ");
    run_aes_share(in,out,key,outex,n,&subbyte_htable,base,nt); 

    printf("  With randomized table inc: ");
    run_aes_share(in,out,key,outex,n,&subbyte_htable_inc,base,nt); 

    printf("  With randomized table word: ");
    run_aes_share(in,out,key,outex,n,&subbyte_htable_word,base,nt);

    printf("  With randomized table word inc: ");
    run_aes_share(in,out,key,outex,n,&subbyte_htable_word_inc,base,nt); 

    printf("  With randomized table common shares: ");
    run_aes_common_share(in,out,key,outex,n,&subbyte_cs_htable,base,nt); 
    
    printf("  With randomized table word common shares: ");
    run_aes_common_share(in,out,key,outex,n,&subbyte_cs_htable_word,base,nt); 

    printf("  With randomized table word inc common shares: ");
    run_aes_common_share(in,out,key,outex,n,&subbyte_cs_htable_word_inc,base,nt); 
   
  }*/