#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <math.h>
#include "aes.h"
#include "aes_rp.h"
#include "aes_rp_prg.h"
#include "share.h"
#include "aes_share.h"
#include "aes_htable.h"
#include "common.h"
#include "prg.h"
#include "cvector.h"
#include "time.h"

#define Experment_num 1000
#define Share_num 3
#define Is_random 1  //控制是否随机明文、密钥和错误,调试用 1:表示随机 0:表示固定
#define Is_print 1 //控制是否打印详细数据，1:表示打印，0:表示不打印
typedef int bool;
#define true 1
#define false 0
#define Cipher_num 10000

int recovery_main_key(byte key_10round[16],byte main_key[16]);

void print_4_by_4(byte temp[16]){
	FILE *fpWrite = fopen("experiment.txt", "a+");
	for(int j=0;j<16;j++){
		printf("0x%02x,",temp[j]);
		fprintf(fpWrite,"0x%02x,",temp[j]);
		if((j+1)%4==0){
			printf("\n");
			fprintf(fpWrite,"\n");
		}
	}
	printf("\n");
	fprintf(fpWrite,"\n");
	fclose(fpWrite);
}

void print_4_by_4_int(int temp[16]){
	FILE *fpWrite = fopen("experiment.txt", "a+");
	for(int j=0;j<16;j++){
		printf("%d ",temp[j]);
		fprintf(fpWrite,"%d ",temp[j]);
		if((j+1)%4==0){
			printf("\n");
			fprintf(fpWrite,"\n");
		}
	}
	printf("\n");
	fprintf(fpWrite,"\n");
	fclose(fpWrite);
}

byte S_Box[256] = {
	0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
	0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
	0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
	0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
	0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
	0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
	0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
	0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
	0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
	0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
	0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
	0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
	0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
	0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
	0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
	0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

struct {
	byte in_diff;
	byte in1;
	byte in2;
	byte out_diff;
	byte out1;
	byte out2;
}in_out_diff[65536];

struct {
	unsigned int value;
	byte in1[2];
	byte in2[2];
	byte in_diff[2];
	byte out1[2];
	byte out2[2];
	byte out_diff[2];
}table[256][256];

struct Different_Cipher{
	byte diff_cipher[2][16];
	int diff_local[4];
};

void diff_table() {//计算差分分布表
	for (int i = 0; i < 256; i++) {
		for (int j = i+1; j < 256; j++) {
			in_out_diff[i*256+j].in1 = i;
			in_out_diff[i*256+j].in2 = j;
			in_out_diff[i*256+j].in_diff = i ^ j;
			in_out_diff[i*256+j].out1 = S_Box[i];
			in_out_diff[i*256+j].out2 = S_Box[j];
			in_out_diff[i*256+j].out_diff = S_Box[i] ^ S_Box[j];
			//printf("%d\n\t%.2x\t%.2x\t%.2x\t%.2x\t%.2x\t%.2x\n", i * 256 + j,in_out_diff[i * 256 + j].in1,in_out_diff[i * 256 + j].in2, in_out_diff[i * 256 + j].in_diff, in_out_diff[i * 256 + j].out1, in_out_diff[i * 256 + j].out2,	in_out_diff[i * 256 + j].out_diff);
			
			table[in_out_diff[i * 256 + j].in_diff][in_out_diff[i * 256 + j].out_diff].in1[table[in_out_diff[i * 256 + j].in_diff][in_out_diff[i * 256 + j].out_diff].value] = in_out_diff[i * 256 + j].in1;
			table[in_out_diff[i * 256 + j].in_diff][in_out_diff[i * 256 + j].out_diff].in2[table[in_out_diff[i * 256 + j].in_diff][in_out_diff[i * 256 + j].out_diff].value] = in_out_diff[i * 256 + j].in2;
			table[in_out_diff[i * 256 + j].in_diff][in_out_diff[i * 256 + j].out_diff].in_diff[table[in_out_diff[i * 256 + j].in_diff][in_out_diff[i * 256 + j].out_diff].value] = in_out_diff[i * 256 + j].in_diff;
			table[in_out_diff[i * 256 + j].in_diff][in_out_diff[i * 256 + j].out_diff].out1[table[in_out_diff[i * 256 + j].in_diff][in_out_diff[i * 256 + j].out_diff].value] = in_out_diff[i * 256 + j].out1;
			table[in_out_diff[i * 256 + j].in_diff][in_out_diff[i * 256 + j].out_diff].out2[table[in_out_diff[i * 256 + j].in_diff][in_out_diff[i * 256 + j].out_diff].value] = in_out_diff[i * 256 + j].out2;
			table[in_out_diff[i * 256 + j].in_diff][in_out_diff[i * 256 + j].out_diff].out_diff[table[in_out_diff[i * 256 + j].in_diff][in_out_diff[i * 256 + j].out_diff].value] = in_out_diff[i * 256 + j].out_diff;
			table[in_out_diff[i * 256 + j].in_diff][in_out_diff[i * 256 + j].out_diff].value++;
		}
	}
}

int random_in_key(byte in[16],byte out[16],byte key[16],byte outex[16],int nt,byte w[176]){
	//随机注入错误
	srand((unsigned)time(NULL) + rand());
	byte loc = 0 + rand() % (256 - 0); 
	byte value = 1 + rand() % (256 - 1); 
	byte rel_value = get_taffineValue(loc);
	set_taffineValue(loc, value);
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

int first_filter_difference_chain(byte delta,byte differential_cipher_4_error[4][4],byte arr_delta[4][4],
	int relationship_delta_difference_cipher[4][4],int diff_delta_count[4],int* appear_4_but_not_match,int* no_chain,
	int* more_chain,int* match_four){
	int num = 0;
	int temp[4] = {0,0,0,0};
	for(int i=0;i<4;i++){//遍历differential_cipher_4_error的第一维
		for(int j=0;j<4;j++){//遍历arr_delta的第一维
			int match_num = 0;
			for(int k=0;k<4;k++){
				if(table[arr_delta[j][k]][differential_cipher_4_error[i][k]].value>=1){
					match_num++;
					//printf("match_num: %d\n",match_num);
				}
			}
			//printf("\n");
			if(match_num == 4){
				relationship_delta_difference_cipher[i][diff_delta_count[i]] = j;
				FILE *fpWrite = fopen("experiment.txt", "a+");
				fprintf(fpWrite,"diff:%d\tdelta:%d\n",i,j);
				fclose(fpWrite);
				printf("diff:%d\tdelta:%d\n",i,j);
				diff_delta_count[i]++;
				if(i==0)temp[0] = 1;
				else if(i==1)temp[1] = 1;
				else if(i==2)temp[2] = 1;
				else if(i==3)temp[3] = 1;
				//break;
			}
		}
	}
	printf("diff_delta_count:\n");
	for(int i=0;i<4;i++){
		printf("%d\n",diff_delta_count[i]);
	}
	if(diff_delta_count[0]==1&&diff_delta_count[1]==1&&diff_delta_count[2]==1&&diff_delta_count[3]==1){
		(*match_four)++;
	}
	else if(diff_delta_count[0]>=1&&diff_delta_count[1]>=1&&diff_delta_count[2]>=1&&diff_delta_count[3]>=1){
		(*more_chain)++;
	}

	FILE *fpWrite = fopen("experiment.txt", "a+");	
	for(int i=0;i<4;i++){
		printf("i:%d\n",i);
		fprintf(fpWrite,"i:%d\n",i);
		for(int j=0;j<diff_delta_count[i];j++){
			printf("relationship_delta_difference_cipher:%d\n",relationship_delta_difference_cipher[i][j]);
			fprintf(fpWrite,"relationship_delta_difference_cipher:%d\n",relationship_delta_difference_cipher[i][j]);
		}
	}
	printf("\n");
	fprintf(fpWrite,"\n");
	printf("relationship_delta_difference_cipher:\n");
	fprintf(fpWrite,"relationship_delta_difference_cipher:\n");
	for(int i=0;i<4;i++){
		for(int j=0;j<4;j++){
			printf("%d,",relationship_delta_difference_cipher[i][j]);
			fprintf(fpWrite,"%d,",relationship_delta_difference_cipher[i][j]);
		}
		printf("\n");
		fprintf(fpWrite,"\n");
	}
	int res = temp[0]+temp[1]+temp[2]+temp[3];
	printf("temp:%d\n",res);
	fprintf(fpWrite,"temp:%d\n",res);
	fclose(fpWrite);
	return res;
}

int later_filter_difference_chain(byte delta,byte differential_cipher_4_error[4][4],byte arr_delta[4][4],
	int relationship_delta_difference_cipher[4][4],int diff_delta_count[4]){
	int num = 0;
	int temp[4] = {0,0,0,0};
	for(int i=0;i<4;i++){//遍历differential_cipher_4_error的第一维
		for(int j=0;j<4;j++){//遍历arr_delta的第一维
			int match_num = 0;
			for(int k=0;k<4;k++){
				if(table[arr_delta[j][k]][differential_cipher_4_error[i][k]].value>=1){
					match_num++;
					//printf("match_num: %d\n",match_num);
				}
			}
			//printf("\n");
			if(match_num == 4){
				relationship_delta_difference_cipher[i][diff_delta_count[i]] = j;
				FILE *fpWrite = fopen("experiment.txt", "a+");
				fprintf(fpWrite,"diff:%d\tdelta:%d\n",i,j);
				fclose(fpWrite);
				printf("diff:%d\tdelta:%d\n",i,j);
				diff_delta_count[i]++;
				if(i==0)temp[0] = 1;
				else if(i==1)temp[1] = 1;
				else if(i==2)temp[2] = 1;
				else if(i==3)temp[3] = 1;
				//break;
			}
		}
	}
	FILE *fpWrite = fopen("experiment.txt", "a+");
	for(int i=0;i<4;i++){
		printf("i:%d\n",i);
		fprintf(fpWrite,"i:%d\n",i);
		for(int j=0;j<diff_delta_count[i];j++){
			printf("relationship_delta_difference_cipher:%d\n",relationship_delta_difference_cipher[i][j]);
			fprintf(fpWrite,"relationship_delta_difference_cipher:%d\n",relationship_delta_difference_cipher[i][j]);
		}
	}
	printf("\n");
	fprintf(fpWrite,"\n");
	printf("relationship_delta_difference_cipher:\n");
	fprintf(fpWrite,"relationship_delta_difference_cipher:\n");
	for(int i=0;i<4;i++){
		for(int j=0;j<4;j++){
			printf("%d,",relationship_delta_difference_cipher[i][j]);
			fprintf(fpWrite,"%d,",relationship_delta_difference_cipher[i][j]);
		}
		printf("\n");
		fprintf(fpWrite,"\n");
	}
	int res = temp[0]+temp[1]+temp[2]+temp[3];
	printf("temp:%d\n",res);
	fprintf(fpWrite,"temp:%d\n",res);
	fclose(fpWrite);
	return res;
}

//动态数组实现，有bug
int encrypt_find_different_dynamic_array(byte in[16],byte out[16],byte key[16],
	byte outex[16],int n,int nt,int base,byte* delta,byte differential_cipher_4_error[4][4]){
	int error_local[16]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};//记录错误的位置用
	int total_cipher_count = 10;//给内存扩容用
	int differential_cipher_4_error_count = 0;
	byte (*stored_cipher)[16] = (byte (*)[16])malloc(sizeof(byte *)*total_cipher_count);
	bool collect_cipher_done = false;//如果找到16个字节都出错，并且也找到第十轮出错（只有一个字节出错）的情况，如果找到了就停止加密
	bool collect_one_error = false;//是否收集到一个错误的情况，即收集到第十轮出错的情况,记得改成false
	int current_cipher_number = 0;
	for(;current_cipher_number<Cipher_num;current_cipher_number++){
		if(current_cipher_number == total_cipher_count){
			printf("要进行扩容了！\n");
			byte (*p_temp)[16] = NULL;
			total_cipher_count+=10;    	  //给内存扩容，一般都是直接扩大为2倍，我这里就加了10个
			p_temp = (byte (*)[16])realloc(stored_cipher,sizeof(byte *)*total_cipher_count);	
			if(p_temp == NULL){
				printf("扩展表内存失败！");
				return 0;
			}
			free(stored_cipher);
			stored_cipher = p_temp;
		}
		run_aes_share(in,out,key,outex,n,&subbyte_rp_share,nt,base);
		for(int i=0;i<16;i++){
			stored_cipher[current_cipher_number][i] = out[i];
		}
		// printf("\n当前已经存储的密文：\n");
		// for(int i=0;i<current_cipher_number+1;i++){
		// 	print_4_by_4(stored_cipher[i]);
		// }
		
		
		for(int i=0;i<current_cipher_number;i++){//把当前密文与之前所有的密文进行比较
			int different_local[4] = {0,0,0,0};
			int different_count = 0;
			for(int j=0;j<16;j++){
				if(stored_cipher[i][j] != stored_cipher[current_cipher_number][j]){
					if(different_count>=4){//记住这个地方的bug！！第三次bug了
						different_count++;
						continue;
					}
					different_local[different_count] = j;
					different_count++;
				}
			}
			if(different_count ==1 && !collect_one_error){//第十轮出错，只有一个字节不同，计算德尔塔用
				printf("只有一个字节不同！\n");
				//第十轮出错，后续使用
				collect_one_error = true;
				*delta = stored_cipher[i][different_local[0]] ^ stored_cipher[current_cipher_number][different_local[0]];
			}
			else if(different_count == 4 &&  (!error_local[different_local[0]] || !error_local[different_local[1]] || 
				!error_local[different_local[2]] || !error_local[different_local[3]])){//第九轮出错，导致密文四个字节不同
				//printf("有四个字节不同！\n");
				for(int q=0;q<4;q++){
					error_local[different_local[q]] = 1;//将本次四个错误字节存起来
					//printf("到这了嘛？%d\n",error_local[different_local[q]]);
				}
				for(int n=0;n<4;n++){//计算四个字节的差分
					differential_cipher_4_error[differential_cipher_4_error_count][n] = stored_cipher[i][different_local[n]] ^
						stored_cipher[current_cipher_number][different_local[n]];
					//printf("差分：%02x\n",differential_cipher_4_error[differential_cipher_4_error_count][n]);
				}
				differential_cipher_4_error_count++;
				if(differential_cipher_4_error_count>=4)break;//!!!!!!!
			}
			else{
				//printf("第%d条密文与第%d条密文有%d字节不同，不是我要找的\n",i+1,current_cipher_number,different_count);
			}
			int sum = 0;
			for(int k=0;k<16;k++){//如果16个字节都找到了，那就停止加密
				sum += error_local[k];
			}
			if((sum == 16) && collect_one_error){
				collect_cipher_done = true;
				printf("收集密文结束！一共加密%d次\n",current_cipher_number);
				break;
			}
		}
		if(collect_cipher_done)break;
	}
	printf("last四个字节的差分：\n");
	for(int i=0;i<4;i++){
		for(int j=0;j<4;j++){
			printf("%02x ",differential_cipher_4_error[i][j]);
		}
		printf("\n");
	}
	printf("\n");
	return current_cipher_number;//返回加密次数
}

int Is_equal(byte a[16],byte b[16]){
	int sum = 0;
	for(int i=0;i<16;i++)
		if(a[i] == b[i])
			sum++;
	if(sum==16)
		return 1;
	return 0;
}

int encrypt_find_different(byte in[16],byte out[16],byte key[16],byte outex[16],int n,int nt,int base,byte* delta,
	byte differential_cipher_4_error[4][4],struct Different_Cipher dc[4],int relationship_delta_difference_cipher[4][4],
	int diff_delta_count[4],int* appear_4_but_not_match,int* no_chain,int* more_chain,int* match_four,byte cipher_verify[16]){//第九轮出错导致密文四个字节不同的差分数组
	int error_local[16]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};//记录错误的位置用
	byte stored_cipher[Cipher_num][16];
	int differential_cipher_4_error_count = 0;//是否已经找到了四对四个字节不同的密文对，取值范围0-3，大于4就break
	bool collect_one_error = false;//是否收集到一个错误的情况，即收集到第十轮出错的情况,记得改成false
	bool collect_cipher_done = false;//如果找到16个字节都出错，并且也找到第十轮出错（只有一个字节出错）的情况，如果找到了就停止加密
	int current_cipher_number = 0;
	int cipher_verify_flag = 0;
	for(;current_cipher_number<Cipher_num;current_cipher_number++){
		FILE *fpWrite ;
		if(Is_print){
			fpWrite= fopen("encrypt_state.txt", "a+");
			fprintf(fpWrite,"第%d次加密状态矩阵:--share----------\n",current_cipher_number);
			fclose(fpWrite);
			run_aes_share_print(in,out,key,outex,n,&subbyte_rp_share_print,nt,base);
		}
		else if(!Is_print){
			run_aes_share(in,out,key,outex,n,&subbyte_rp_share,nt,base);
		}
		for(int i=0;i<16;i++){
			stored_cipher[current_cipher_number][i] = out[i];
		}
		int cipher_verify_num = 0;
		for(int i=0;i<current_cipher_number;i++){
			int different_local[4] = {0,0,0,0};
			int different_count = 0;
			for(int k=0;k<16;k++){
				if((stored_cipher[i][k]) != (stored_cipher[current_cipher_number][k])){
					if(different_count>=4){//记住这个地方的bug！！第三次bug了
						different_count++;
						break;
					}
					different_local[different_count] = k;
					different_count++;
				}
			}
			if((different_count == 0) && (cipher_verify_flag == 0)){//记录cipher_verify，用于验证
				if(Is_equal(cipher_verify,out)){
					cipher_verify_num++;
					if(cipher_verify_num == 5){//如果已经有三条密文相同了,33333
						cipher_verify_flag = 1;
						fpWrite = fopen("experiment.txt", "a+");
						printf("cipher_verify:\ni:%d,current_cipher_number：%d\n",i,current_cipher_number);
						fprintf(fpWrite,"cipher_verify:\ni:%d,current_cipher_number%d\n",i,current_cipher_number);
						for(int i=0;i<16;i++){
							printf("%02x ",cipher_verify[i]);
							fprintf(fpWrite,"%02x ",cipher_verify[i]);
							if((i+1)%4==0){
								printf("\n");
								fprintf(fpWrite,"\n");
							}
						}
						printf("\n");
						fprintf(fpWrite,"\n");
						fclose(fpWrite);
					}
				}
				else {
					cipher_verify_num = 2;
					for(int i=0;i<16;i++){
						cipher_verify[i] = out[i];
					}
				}
			}
			else if((different_count ==1) && !collect_one_error){//第十轮出错，只有一个字节不同，计算德尔塔用
				collect_one_error = true;
				*delta = stored_cipher[i][different_local[0]] ^ stored_cipher[current_cipher_number][different_local[0]];
			}
			else if(different_count == 4 && (!error_local[different_local[0]] || !error_local[different_local[1]] || 
				!error_local[different_local[2]] || !error_local[different_local[3]])){//第九轮出错，导致密文四个字节不同
				if(!((different_local[0]==0&&different_local[1]==7&&different_local[2]==10&&different_local[3]==13)||
					(different_local[0]==1&&different_local[1]==4&&different_local[2]==11&&different_local[3]==14)||
					(different_local[0]==2&&different_local[1]==5&&different_local[2]==8&&different_local[3]==15)||
					(different_local[0]==3&&different_local[1]==6&&different_local[2]==9&&different_local[3]==12)))
					break;//把那些错误位置不是0，7，10，13；1，4，11，14；2，5，8，15；3，6，9，12的排除
				
				FILE *fpWrite = fopen("experiment.txt", "a+");
				printf("第%d条密文与第%d条密文有%d字节不同!\n",i,current_cipher_number,different_count);
				fprintf(fpWrite,"第%d条密文与第%d条密文有%d字节不同!\n",i,current_cipher_number,different_count);
				printf("第%d条:\n",i);
				fprintf(fpWrite,"第%d条:\n",i);
				fclose(fpWrite);
				print_4_by_4(stored_cipher[i]);
				fpWrite = fopen("experiment.txt", "a+");
				printf("第%d条:\n",current_cipher_number);
				fprintf(fpWrite,"第%d条:\n",current_cipher_number);
				fclose(fpWrite);
				print_4_by_4(stored_cipher[current_cipher_number]);
				
				for(int q=0;q<4;q++){
					error_local[different_local[q]] = 1;//将本次四个错误字节位置存起来
					dc[differential_cipher_4_error_count].diff_local[q] = different_local[q];//将两条只有四个字节不同的密文的不同位置存储起来
					differential_cipher_4_error[differential_cipher_4_error_count][q] = stored_cipher[i][different_local[q]] ^
						stored_cipher[current_cipher_number][different_local[q]];//计算四个字节的差分
					//printf("差分：%02x\n",differential_cipher_4_error[differential_cipher_4_error_count][n]);
				}
				for(int y=0;y<16;y++){//将两条只有四个字节不同的密文存储起来
					dc[differential_cipher_4_error_count].diff_cipher[0][y] = stored_cipher[i][y];
					dc[differential_cipher_4_error_count].diff_cipher[1][y] = stored_cipher[current_cipher_number][y];
				}
				printf("此时different_local: ");
				printf("%d %d %d %d\n",different_local[0],different_local[1],different_local[2],different_local[3]);
				printf("error_local:\n");
				fpWrite = fopen("experiment.txt", "a+");
				fprintf(fpWrite,"此时different_local: ");
				fprintf(fpWrite,"%d %d %d %d\n",different_local[0],different_local[1],different_local[2],different_local[3]);
				fprintf(fpWrite,"error_local:\n");
				fclose(fpWrite);
				print_4_by_4_int(error_local);
				differential_cipher_4_error_count++;
				if(differential_cipher_4_error_count>=4)break;//!!!!!!!
			}
			else{
				// printf("第%d条密文与第%d条密文有%d字节不同，不是我要找的\n",i,current_cipher_number,different_count);
				// printf("第%d条:\n",i);
				// print_4_by_4(stored_cipher[i]);
				// printf("第%d条:\n",current_cipher_number);
				// print_4_by_4(stored_cipher[current_cipher_number]);
			}
			
			int sum = 0;
			for(int k=0;k<16;k++){//如果16个字节都找到了，那就停止加密
				sum += error_local[k];
			}
			if((sum == 16) && collect_one_error && cipher_verify_flag){
				collect_cipher_done = true;
				fpWrite = fopen("experiment.txt", "a+");
				printf("收集密文暂时结束！一共加密%d次\n",current_cipher_number);
				fprintf(fpWrite,"收集密文暂时结束！一共加密%d次\n",current_cipher_number);
				fclose(fpWrite);
				break;
			}
		}
		if(collect_cipher_done)break;
	}
	FILE *fpWrite = fopen("experiment.txt", "a+");
	printf("last四个字节的差分：\n");
	fprintf(fpWrite,"last四个字节的差分：\n");
	for(int i=0;i<4;i++){
		for(int j=0;j<4;j++){
			printf("%02x ",differential_cipher_4_error[i][j]);
			fprintf(fpWrite,"%02x ",differential_cipher_4_error[i][j]);
		}
		printf("\n");
		fprintf(fpWrite,"\n");
	}
	printf("\n");
	fprintf(fpWrite,"\n");
	fclose(fpWrite);
	byte delta_value = *delta;
	byte delta2 = mult(2 , delta_value);
	byte delta3 = mult(3 , delta_value);
	byte arr_delta[4][4] = {{delta2,delta3,delta_value,delta_value},{delta_value,delta2,delta3,delta_value},
		{delta_value,delta_value,delta2,delta3},{delta3,delta_value,delta_value,delta2}};
	fpWrite = fopen("experiment.txt", "a+");
	printf("delta:0x%02x\t2*delta:0x%02x\t3*delta:0x%02x\n",delta_value,delta2,delta3);
	fprintf(fpWrite,"delta:0x%02x\t2*delta:0x%02x\t3*delta:0x%02x\n",delta_value,delta2,delta3);
	fclose(fpWrite);
	int return_num = first_filter_difference_chain(delta_value,differential_cipher_4_error,arr_delta,
	relationship_delta_difference_cipher,diff_delta_count,appear_4_but_not_match,no_chain,more_chain,match_four);

	int no_chain_flag = 0;
	while(return_num <4){
		no_chain_flag = 1;
		for(int rddc=0;rddc<4;rddc++){
			if(relationship_delta_difference_cipher[rddc][0]== -1){
				fpWrite = fopen("experiment.txt", "a+");
				printf("继续找：\n");
				fprintf(fpWrite,"继续找：\n");
				fclose(fpWrite);	
				for(int h=0;h<4;h++){
					diff_delta_count[h] = 0;
				}
				bool flag = false;
				for(;current_cipher_number<Cipher_num&&!flag;current_cipher_number++){
					//fpWrite = fopen("encrypt_state.txt", "a+");
					//fprintf(fpWrite,"第%d次加密状态矩阵:--share----------\n",current_cipher_number);
					//fclose(fpWrite);
					run_aes_share(in,out,key,outex,n,&subbyte_rp_share,nt,base); 
					for(int i=0;i<16;i++){
						stored_cipher[current_cipher_number][i] = out[i];
					}
					for(int i=0;i<current_cipher_number;i++){
						int different_local[4] = {0,0,0,0};
						int different_count = 0;
						for(int k=0;k<16;k++){
							if((stored_cipher[i][k]) != (stored_cipher[current_cipher_number][k])){
								if(different_count>=4){//记住这个地方的bug！！第三次bug了
									different_count++;
									continue;
								}
								different_local[different_count] = k;
								different_count++;
							}
						}
						if(different_count == 4 && dc[rddc].diff_local[0]==different_local[0] && dc[rddc].diff_local[1]==different_local[1] &&
							dc[rddc].diff_local[2]==different_local[2] && dc[rddc].diff_local[3]==different_local[3]){
							fpWrite = fopen("experiment.txt", "a+");
							printf("第%d条密文与第%d条密文有%d字节不同!\n",i,current_cipher_number,different_count);
							fprintf(fpWrite,"第%d条密文与第%d条密文有%d字节不同!\n",i,current_cipher_number,different_count);
							printf("第%d条:\n",i);
							fprintf(fpWrite,"第%d条:\n",i);
							fclose(fpWrite);
							print_4_by_4(stored_cipher[i]);
							fpWrite = fopen("experiment.txt", "a+");
							printf("第%d条:\n",current_cipher_number);
							fprintf(fpWrite,"第%d条:\n",current_cipher_number);
							fclose(fpWrite);
							print_4_by_4(stored_cipher[current_cipher_number]);
								
							for(int q=0;q<4;q++){
								error_local[different_local[q]] = 1;//将本次四个错误字节位置存起来
								dc[rddc].diff_local[q] = different_local[q];//将两条只有四个字节不同的密文的不同位置存储起来
								differential_cipher_4_error[rddc][q] = stored_cipher[i][different_local[q]] ^
									stored_cipher[current_cipher_number][different_local[q]];//计算四个字节的差分
								//printf("差分：%02x\n",differential_cipher_4_error[differential_cipher_4_error_count][n]);
							}
							for(int y=0;y<16;y++){//将两条只有四个字节不同的密文存储起来
								dc[rddc].diff_cipher[0][y] = stored_cipher[i][y];
								dc[rddc].diff_cipher[1][y] = stored_cipher[current_cipher_number][y];
							}
							flag = 1;
							// fpWrite = fopen("experiment.txt", "a+");
							// printf("last四个字节的差分：\n");
							// fprintf(fpWrite,"last四个字节的差分：\n");
							// for(int i=0;i<4;i++){
							// 	for(int j=0;j<4;j++){
							// 		printf("%02x ",differential_cipher_4_error[i][j]);
							// 		fprintf(fpWrite,"%02x ",differential_cipher_4_error[i][j]);
							// 	}
							// 	printf("\n");
							// 	fprintf(fpWrite,"\n");
							// }
							// printf("\n");
							// fprintf(fpWrite,"\n");
							// fclose(fpWrite);
							break;
						}
					}
				}
			}
		}
		return_num = later_filter_difference_chain(delta_value,differential_cipher_4_error,arr_delta,
		relationship_delta_difference_cipher,diff_delta_count);
	}
	if(no_chain_flag==1)(*no_chain)++;
	fpWrite = fopen("experiment.txt", "a+");
	printf("last四个字节的差分：\n");
	fprintf(fpWrite,"last四个字节的差分：\n");
	for(int i=0;i<4;i++){
		for(int j=0;j<4;j++){
			printf("%02x ",differential_cipher_4_error[i][j]);
			fprintf(fpWrite,"%02x ",differential_cipher_4_error[i][j]);
		}
		printf("\n");
		fprintf(fpWrite,"\n");
	}
	printf("\n");
	fprintf(fpWrite,"\n");
	printf("收集密文最终结束！一共加密%d次\n\n",current_cipher_number);
	fprintf(fpWrite,"收集密文最终结束！一共加密%d次\n\n",current_cipher_number);
	fclose(fpWrite);
	return current_cipher_number;//返回加密次数
}

int verify_online_key(byte guess_key_10round[16][16],byte key_10round[16],byte w[176],int candidiate_key_count[16],
	int* success_num,int* fail_num,byte cipher_verify[16],byte in[16],int n,int nt,int base,byte reall_main_key[16],int *out_time_num){
	int verify_encrypt_num = 0;
	for(int a0=0;a0<candidiate_key_count[0];a0++){
		printf("\na0:%d\t",a0);
		for(int a1=0;a1<candidiate_key_count[1];a1++){
			printf("a1:%d ",a1);
			for(int a2=0;a2<candidiate_key_count[2];a2++){
				for(int a3=0;a3<candidiate_key_count[3];a3++){
					for(int a4=0;a4<candidiate_key_count[4];a4++){
						for(int a5=0;a5<candidiate_key_count[5];a5++){
							for(int a6=0;a6<candidiate_key_count[6];a6++){
								for(int a7=0;a7<candidiate_key_count[7];a7++){
									for(int a8=0;a8<candidiate_key_count[8];a8++){
										for(int a9=0;a9<candidiate_key_count[9];a9++){
											for(int a10=0;a10<candidiate_key_count[10];a10++){
												for(int a11=0;a11<candidiate_key_count[11];a11++){
													for(int a12=0;a12<candidiate_key_count[12];a12++){
														for(int a13=0;a13<candidiate_key_count[13];a13++){
															for(int a14=0;a14<candidiate_key_count[14];a14++){
																for(int a15=0;a15<candidiate_key_count[15];a15++){
																	verify_encrypt_num++;
																	if(verify_encrypt_num>=33554432){
																		/*
																			2的30次方1073741824  
																			2的20次方1048576
																			2的22次方4194304
																			2的23次方8388608
																			2的25次方33554432 理论上这个的超时时间应该是1800秒
																		*/
																		(*out_time_num)++;
																		FILE *fpWrite = fopen("experiment.txt", "a+");
																		printf("超时超时！\n");
																		fprintf(fpWrite,"超时超时！\n");
																		fclose(fpWrite);
																		return -3;
																	}
																	// if(guess_key_10round[0][a0]==w[160]&& 
																	// 	guess_key_10round[1][a1]==w[161]&&
																	// 	guess_key_10round[2][a2]==w[162]&&
																	// 	guess_key_10round[3][a3]==w[163]&&
																	// 	guess_key_10round[4][a4]==w[164]&&
																	// 	guess_key_10round[5][a5]==w[165]&&
																	// 	guess_key_10round[6][a6]==w[166]&&
																	// 	guess_key_10round[7][a7]==w[167]&&
																	// 	guess_key_10round[8][a8]==w[168]&&
																	// 	guess_key_10round[9][a9]==w[169]&&
																	// 	guess_key_10round[10][a10]==w[170]&&
																	// 	guess_key_10round[11][a11]==w[171]&&
																	// 	guess_key_10round[12][a12]==w[172]&&
																	// 	guess_key_10round[13][a13]==w[173]&&
																	// 	guess_key_10round[14][a14]==w[174]&&
																	// 	guess_key_10round[15][a15]==w[175]){
																	// 		count_equal_num = 16;
																	// }
																	int count_equal_num = 0;
																	byte guess_key[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
																	guess_key[0] = guess_key_10round[0][a0];
																	guess_key[1] = guess_key_10round[1][a1];
																	guess_key[2] = guess_key_10round[2][a2];
																	guess_key[3] = guess_key_10round[3][a3];
																	guess_key[4] = guess_key_10round[4][a4];
																	guess_key[5] = guess_key_10round[5][a5];
																	guess_key[6] = guess_key_10round[6][a6];
																	guess_key[7] = guess_key_10round[7][a7];
																	guess_key[8] = guess_key_10round[8][a8];
																	guess_key[9] = guess_key_10round[9][a9];
																	guess_key[10] = guess_key_10round[10][a10];
																	guess_key[11] = guess_key_10round[11][a11];
																	guess_key[12] = guess_key_10round[12][a12];
																	guess_key[13] = guess_key_10round[13][a13];
																	guess_key[14] = guess_key_10round[14][a14];
																	guess_key[15] = guess_key_10round[15][a15];
																	byte out[16] =  {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
																	byte outex[16]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
																	byte guess_main_key[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
																	recovery_main_key(guess_key,guess_main_key);
																	run_aes_share(in,out,guess_main_key,outex,n,&subbyte_rp_share,nt,base); 
																	// FILE *fpWrite = fopen("encrypt_state.txt", "a+");
																	// fprintf(fpWrite,"我要的数据是：\n");
																	// fclose(fpWrite);
																	// fpWrite = fopen("experiment.txt", "a+");
																	// printf("明文是：\n");
																	// fprintf(fpWrite,"明文是：\n");
																	// print_4_by_4(in);
																	// printf("初始密钥是：\n");
																	// fprintf(fpWrite,"初始密钥是：\n");
																	// print_4_by_4(guess_main_key);
																	// printf("用猜测的密钥加密得到的密文是：\n");
																	// fprintf(fpWrite,"用猜测的密钥加密得到的密文是：\n");
																	// print_4_by_4(out);
																	// fclose(fpWrite);
																	for(int o=0;o<16;o++){
																		if(cipher_verify[o]==out[o]){
																			count_equal_num++;
																		}
																	}
																	if(count_equal_num==16){
																		printf("进来了");
																		int key_equal_num = 0;
																		for(int k=0;k<16;k++){
																			if(guess_main_key[k]==reall_main_key[k]){
																				key_equal_num++;
																			}
																		}
																		if(key_equal_num==16){
																			FILE *fpWrite = fopen("experiment.txt", "a+");
																			printf("成功成功！！！\n");
																			fprintf(fpWrite,"成功成功！！！\n");
																			printf("\n恢复密钥成功！\n第十轮子密钥是：\n");
																			fprintf(fpWrite,"\n恢复密钥成功！\n第十轮子密钥是：\n");
																			(*success_num)++;
																			key_10round[0] = guess_key_10round[0][a0];
																			key_10round[1] = guess_key_10round[1][a1];
																			key_10round[2] = guess_key_10round[2][a2];
																			key_10round[3] = guess_key_10round[3][a3];
																			key_10round[4] = guess_key_10round[4][a4];
																			key_10round[5] = guess_key_10round[5][a5];
																			key_10round[6] = guess_key_10round[6][a6];
																			key_10round[7] = guess_key_10round[7][a7];
																			key_10round[8] = guess_key_10round[8][a8];
																			key_10round[9] = guess_key_10round[9][a9];
																			key_10round[10] = guess_key_10round[10][a10];
																			key_10round[11] = guess_key_10round[11][a11];	
																			key_10round[12] = guess_key_10round[12][a12];
																			key_10round[13] = guess_key_10round[13][a13];
																			key_10round[14] = guess_key_10round[14][a14];
																			key_10round[15] = guess_key_10round[15][a15];
																			for(int y=0;y<16;y++){
																				printf("%02x,",key_10round[y]);
																				fprintf(fpWrite,"%02x,",key_10round[y]);
																				if((y+1)%4==0){
																					printf("\n");
																					fprintf(fpWrite,"\n");
																				}
																			}
																			printf("\n求得初始密钥是：\n");
																			fprintf(fpWrite,"\n求得初始密钥是：\n");	
																			for(int i=0;i<16;i++){
																				printf("%02x,",guess_main_key[i]);
																				fprintf(fpWrite,"%02x,",guess_main_key[i]);
																				if((i+1)%4==0){
																					printf("\n");
																					fprintf(fpWrite,"\n");
																				}
																			}
																			fclose(fpWrite);
																			return 0;
																		}
																		else{
																			FILE *fpWrite = fopen("experiment.txt", "a+");
																			printf("偶然失败！！！\n");
																			fprintf(fpWrite,"偶然失败！！！\n");
																			return -2;
																		}
																	}
																}
															}
														}
													}
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}
	FILE *fpWrite = fopen("experiment.txt", "a+");
	printf("失败!!!\n");
	fprintf(fpWrite,"失败！！！\n");
	fclose(fpWrite);
	(*fail_num)++;
	return -1;
}

int verify_offline_key(byte guess_key_10round[16][16],byte key_10round[16],byte w[176],int candidiate_key_count[16],
	int* success_num,int* fail_num,byte cipher_verify[16],byte in[16],int n,int nt,int base,byte reall_main_key[16],int *out_time_num){
	int verify_encrypt_num = 0;	
	for(int a0=0;a0<candidiate_key_count[0];a0++){
		printf("\na0:%d\t",a0);
		for(int a1=0;a1<candidiate_key_count[1];a1++){
			printf("a1:%d ",a1);
			for(int a2=0;a2<candidiate_key_count[2];a2++){
				for(int a3=0;a3<candidiate_key_count[3];a3++){
					for(int a4=0;a4<candidiate_key_count[4];a4++){
						for(int a5=0;a5<candidiate_key_count[5];a5++){
							for(int a6=0;a6<candidiate_key_count[6];a6++){
								for(int a7=0;a7<candidiate_key_count[7];a7++){
									for(int a8=0;a8<candidiate_key_count[8];a8++){
										for(int a9=0;a9<candidiate_key_count[9];a9++){
											for(int a10=0;a10<candidiate_key_count[10];a10++){
												for(int a11=0;a11<candidiate_key_count[11];a11++){
													for(int a12=0;a12<candidiate_key_count[12];a12++){
														for(int a13=0;a13<candidiate_key_count[13];a13++){
															for(int a14=0;a14<candidiate_key_count[14];a14++){
																for(int a15=0;a15<candidiate_key_count[15];a15++){
																	verify_encrypt_num++;
																	if(verify_encrypt_num>=33554432){
																		/*
																			2的30次方1073741824  
																			2的20次方1048576
																			2的22次方4194304
																			2的23次方8388608，超时时间大约是不到500秒
																			2的25次方33554432 理论上这个的超时时间应该是1800秒
																		*/
																		(*out_time_num)++;
																		FILE *fpWrite = fopen("experiment.txt", "a+");
																		printf("超时超时！\n");
																		fprintf(fpWrite,"超时超时！\n");
																		fclose(fpWrite);
																		return -3;
																	}
																	int count_equal_num = 0;
																	byte guess_key[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
																	guess_key[0] = guess_key_10round[0][a0];
																	guess_key[1] = guess_key_10round[1][a1];
																	guess_key[2] = guess_key_10round[2][a2];
																	guess_key[3] = guess_key_10round[3][a3];
																	guess_key[4] = guess_key_10round[4][a4];
																	guess_key[5] = guess_key_10round[5][a5];
																	guess_key[6] = guess_key_10round[6][a6];
																	guess_key[7] = guess_key_10round[7][a7];
																	guess_key[8] = guess_key_10round[8][a8];
																	guess_key[9] = guess_key_10round[9][a9];
																	guess_key[10] = guess_key_10round[10][a10];
																	guess_key[11] = guess_key_10round[11][a11];
																	guess_key[12] = guess_key_10round[12][a12];
																	guess_key[13] = guess_key_10round[13][a13];
																	guess_key[14] = guess_key_10round[14][a14];
																	guess_key[15] = guess_key_10round[15][a15];
																	byte out[16] =  {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
																	byte outex[16]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
																	byte guess_main_key[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
																	recovery_main_key(guess_key,guess_main_key);
																	run_aes_share_no_error(in,out,guess_main_key,outex,n,&subbyte_rp_share_no_error,nt,base); 
																	// if(guess_key_10round[0][a0]==w[160]&& 
																	// 	guess_key_10round[1][a1]==w[161]&&
																	// 	guess_key_10round[2][a2]==w[162]&&
																	// 	guess_key_10round[3][a3]==w[163]&&
																	// 	guess_key_10round[4][a4]==w[164]&&
																	// 	guess_key_10round[5][a5]==w[165]&&
																	// 	guess_key_10round[6][a6]==w[166]&&
																	// 	guess_key_10round[7][a7]==w[167]&&
																	// 	guess_key_10round[8][a8]==w[168]&&
																	// 	guess_key_10round[9][a9]==w[169]&&
																	// 	guess_key_10round[10][a10]==w[170]&&
																	// 	guess_key_10round[11][a11]==w[171]&&
																	// 	guess_key_10round[12][a12]==w[172]&&
																	// 	guess_key_10round[13][a13]==w[173]&&
																	// 	guess_key_10round[14][a14]==w[174]&&
																	// 	guess_key_10round[15][a15]==w[175]){
																			//count_equal_num = 16;
																	// FILE *fpWrite = fopen("encrypt_state.txt", "a+");
																	// fprintf(fpWrite,"我要的数据是：\n");
																	// fclose(fpWrite);
																	// fpWrite = fopen("experiment.txt", "a+");
																	// printf("明文是：\n");
																	// fprintf(fpWrite,"明文是：\n");
																	// fclose(fpWrite);
																	// print_4_by_4(in);
																	// fpWrite = fopen("experiment.txt", "a+");
																	// printf("初始密钥是：\n");
																	// fprintf(fpWrite,"初始密钥是：\n");
																	// fclose(fpWrite);
																	// print_4_by_4(guess_main_key);
																	// fpWrite = fopen("experiment.txt", "a+");
																	// printf("用猜测的密钥加密得到的密文是：\n");
																	// fprintf(fpWrite,"用猜测的密钥加密得到的密文是：\n");
																	// fclose(fpWrite);
																	// print_4_by_4(out);
																	// fpWrite = fopen("experiment.txt", "a+");
																	// printf("cipher_verify:\n");
																	// fprintf(fpWrite,"cipher_verify:\n");
																	// fclose(fpWrite);
																	// print_4_by_4(cipher_verify);
																	for(int o=0;o<16;o++){
																		if(cipher_verify[o]==out[o]){
																			count_equal_num++;
																		}
																	}
																	if(count_equal_num==16){
																		printf("进来了\n");
																		int key_equal_num = 0;
																		for(int k=0;k<16;k++){
																			if(guess_main_key[k]==reall_main_key[k]){
																				key_equal_num++;
																			}
																		}
																		if(key_equal_num==16){
																			FILE *fpWrite = fopen("experiment.txt", "a+");
																			printf("成功成功！！！\n");
																			fprintf(fpWrite,"成功成功！！！\n");
																			printf("\n恢复密钥成功！\n第十轮子密钥是：\n");
																			fprintf(fpWrite,"\n恢复密钥成功！\n第十轮子密钥是：\n");
																			(*success_num)++;
																			key_10round[0] = guess_key_10round[0][a0];
																			key_10round[1] = guess_key_10round[1][a1];
																			key_10round[2] = guess_key_10round[2][a2];
																			key_10round[3] = guess_key_10round[3][a3];
																			key_10round[4] = guess_key_10round[4][a4];
																			key_10round[5] = guess_key_10round[5][a5];
																			key_10round[6] = guess_key_10round[6][a6];
																			key_10round[7] = guess_key_10round[7][a7];
																			key_10round[8] = guess_key_10round[8][a8];
																			key_10round[9] = guess_key_10round[9][a9];
																			key_10round[10] = guess_key_10round[10][a10];
																			key_10round[11] = guess_key_10round[11][a11];	
																			key_10round[12] = guess_key_10round[12][a12];
																			key_10round[13] = guess_key_10round[13][a13];
																			key_10round[14] = guess_key_10round[14][a14];
																			key_10round[15] = guess_key_10round[15][a15];
																			for(int y=0;y<16;y++){
																				printf("%02x,",key_10round[y]);
																				fprintf(fpWrite,"%02x,",key_10round[y]);
																				if((y+1)%4==0){
																					printf("\n");
																					fprintf(fpWrite,"\n");
																				}
																			}
																			printf("\n求得初始密钥是：\n");
																			fprintf(fpWrite,"\n求得初始密钥是：\n");	
																			for(int i=0;i<16;i++){
																				printf("%02x,",guess_main_key[i]);
																				fprintf(fpWrite,"%02x,",guess_main_key[i]);
																				if((i+1)%4==0){
																					printf("\n");
																					fprintf(fpWrite,"\n");
																				}
																			}
																			fclose(fpWrite);
																			return 0;
																		}
																		else{
																			FILE *fpWrite = fopen("experiment.txt", "a+");
																			printf("偶然失败！！！\n");
																			fprintf(fpWrite,"偶然失败！！！\n");
																			fclose(fpWrite);
																			return -2;
																		}
																	}
																}
															}
														}
													}
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}
	FILE *fpWrite = fopen("experiment.txt", "a+");
	printf("失败!!!\n");
	fprintf(fpWrite,"失败！！！\n");
	fclose(fpWrite);
	(*fail_num)++;
	return -1;
}

int recovery_10round_key(byte delta,byte differential_cipher_4_error[4][4],byte arr_delta[4][4],
	int relationship_delta_difference_cipher[4][4],struct Different_Cipher dc[4],byte guess_key_10round[16][16],
	byte key_10round[16],byte w[176],int diff_delta_count[4],int* success_num,int* fail_num,byte cipher_verify[16]
	,byte in[16],int n,int nt,int base,byte reall_main_key[16],int *out_time_num){
	int candidiate_key_count[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
	for(int i=0;i<4;i++){//遍历四对密文that有四个字节不同的
		for(int j=0;j<4;j++){//遍历每对（有四个字节不同的）密文的每一对不同字节
			int candidate_count = 0;
			for(int diff=0;diff<diff_delta_count[i];diff++){
				for(int k=0;k<16;k++){//遍历错误字节位置,即要恢复的密钥的字节位置
					if(dc[i].diff_local[j] == k && relationship_delta_difference_cipher[i][diff]!= -1){
						if(table[arr_delta[relationship_delta_difference_cipher[i][diff]][j]][differential_cipher_4_error[i][j]].value == 1){
							byte out1 = table[arr_delta[relationship_delta_difference_cipher[i][diff]][j]][(int)differential_cipher_4_error[i][j]].out1[0];
							printf("第十轮子密钥第%2d个字节可能是：%02x %02x\n",k,out1 ^ dc[i].diff_cipher[0][k],out1 ^ dc[i].diff_cipher[1][k]);
							FILE *fpWrite = fopen("experiment.txt", "a+");
							fprintf(fpWrite,"第十轮子密钥第%2d个字节可能是：%02x %02x\n",k,out1 ^ dc[i].diff_cipher[0][k],out1 ^ dc[i].diff_cipher[1][k]);
							fclose(fpWrite);
							guess_key_10round[k][candidate_count++] = out1 ^ dc[i].diff_cipher[0][k];
							guess_key_10round[k][candidate_count++] = out1 ^ dc[i].diff_cipher[1][k];
							candidiate_key_count[k] = candidate_count;
						}
						else if(table[arr_delta[relationship_delta_difference_cipher[i][diff]][j]][differential_cipher_4_error[i][j]].value == 2){
							byte out1 = table[arr_delta[relationship_delta_difference_cipher[i][diff]][j]][(int)differential_cipher_4_error[i][j]].out1[0];
							byte out2 = table[arr_delta[relationship_delta_difference_cipher[i][diff]][j]][(int)differential_cipher_4_error[i][j]].out2[0];
							byte out3 = table[arr_delta[relationship_delta_difference_cipher[i][diff]][j]][(int)differential_cipher_4_error[i][j]].out1[1];
							byte out4 = table[arr_delta[relationship_delta_difference_cipher[i][diff]][j]][(int)differential_cipher_4_error[i][j]].out2[1];
							printf("第十轮子密钥第%2d个字节可能是：%02x %02x %02x %02x\n",k,out1 ^ dc[i].diff_cipher[0][k],
								out1 ^ dc[i].diff_cipher[1][k],out3 ^ dc[i].diff_cipher[0][k],out3 ^ dc[i].diff_cipher[1][k]);
							FILE *fpWrite = fopen("experiment.txt", "a+");
							fprintf(fpWrite,"第十轮子密钥第%2d个字节可能是：%02x %02x %02x %02x\n",k,out1 ^ dc[i].diff_cipher[0][k],
								out1 ^ dc[i].diff_cipher[1][k],out3 ^ dc[i].diff_cipher[0][k],out3 ^ dc[i].diff_cipher[1][k]);
							fclose(fpWrite);
							guess_key_10round[k][candidate_count++] = out1 ^ dc[i].diff_cipher[0][k];
							guess_key_10round[k][candidate_count++] = out1 ^ dc[i].diff_cipher[1][k];
							guess_key_10round[k][candidate_count++] = out3 ^ dc[i].diff_cipher[0][k];
							guess_key_10round[k][candidate_count++] = out3 ^ dc[i].diff_cipher[1][k];
							candidiate_key_count[k] = candidate_count;
						}
						else{
							printf("都不是\n");
							FILE *fpWrite = fopen("experiment.txt", "a+");
							fprintf(fpWrite,"都不是\n");
							fclose(fpWrite);
						}
						break;
					}
				}
			}
		}
	}
	verify_offline_key(guess_key_10round,key_10round,w,candidiate_key_count,success_num,fail_num,cipher_verify,in,n,nt,base,reall_main_key,out_time_num);
	return 0;
}

int recovery_main_key(byte key_10round[16],byte main_key[16]){
	byte temp[4];
	byte w[176];
	byte rcon[10];
	setrcon(rcon);
	
	for(int i=0;i<16;i++)
		w[160+i]=key_10round[i];

	for(int i=156;i>=0;i-=4){
		for(int j=0;j<4;j++)
			temp[j]=w[i+12+j];
		if((i % 16)==0){
			temp[0]=subbyte(w[i+13]) ^ rcon[i/16];
			temp[1]=subbyte(w[i+14]);
			temp[2]=subbyte(w[i+15]);
			temp[3]=subbyte(w[i+12]);
		}
		for(int j=0;j<4;j++)
			w[i+j]=w[i+j+16] ^ temp[j];
	}

	for(int i=0;i<16;i++){
		main_key[i] = w[i];
	}
	// printf("求得初始密钥是：\n");	
	// for(int i=0;i<16;i++){
	// 	printf("%02x,",w[i]);
	// 	if((i+1)%4==0)printf("\n");
	// }
	return 0;
}

int test_key(byte in[16],byte out[16],byte key[16],byte outex[16],int n,int nt,int base,byte w[176]){
	printf("**********开始线***********\n");
	FILE *fpWrite = fopen("experiment.txt", "a+");
	fprintf(fpWrite,"**********开始线***********\n");
	fclose(fpWrite);
	run_aes(&aes_rp,in,out,key,outex,nt,base,w);
	// run_aes_share(in,out,key,outex,n,&subbyte_rp_share,nt,base);
	// printf("密文是：\n");
	// print_4_by_4(out);
	printf("---------结束线-====------\n");
	fpWrite = fopen("experiment.txt", "a+");
	fprintf(fpWrite,"---------结束线-====------\n");
	fclose(fpWrite);
	return 0;
}

int main(){
	clock_t start,middle1,middle2,finish;
   	double  duration;
	start = clock();
  	int n=Share_num;//share的个数
	int base = 1;
  	int nt=10;
	diff_table();
	int all_encrypt_num[Experment_num];
	double excute_time[Experment_num];//每次实验的执行时间，先不统计，因为现在还涉及读写文件，会消耗大量时间
	int success_num = 0;//成功的次数
	int fail_num = 0;//失败的次数
	int appear_4_but_not_match = 0;//
	int no_chain_num = 0;//找不到链的情况（继续找的情况）
	int more_chain_num = 0;//匹配多条链的情况
	int match_four_num = 0;//刚好匹配四条链的情况
	int invalid_error_num = 0;//注入无效错误的情况
	int out_time_num = 0;//超时的次数
	for(int e=0;e<Experment_num;e++){
		middle1 = clock();
		FILE *fpWrite ;
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
			relationship_delta_difference_cipher,diff_delta_count,&appear_4_but_not_match,&no_chain_num,&more_chain_num,&match_four_num,cipher_verify);	
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
		recovery_10round_key(delta,differential_cipher_4_error,arr_delta,relationship_delta_difference_cipher,dc,
			guess_key_10round,key_10round,w,diff_delta_count,&success_num,&fail_num,cipher_verify,in,n,nt,base,key,&out_time_num);
		recovery_main_key(key_10round,main_key);
		for(int i=0;i<256;i++){	
			taffine[i] = taffine_copy[i];//恢复仿射变换表
		}
		middle2 = clock();
		excute_time[e] = (double)(middle2 - middle1)/ CLOCKS_PER_SEC;
		fpWrite = fopen("experiment.txt", "a+");
		printf("success_num:%d\n",success_num);
		fprintf(fpWrite,"success_num:%d\n",success_num);
		printf("fail_num:%d\n",fail_num);
		fprintf(fpWrite,"fail_num:%d\n",fail_num);
		printf("out_time_num:%d\n",out_time_num);
		fprintf(fpWrite,"out_time_num:%d\n",out_time_num);
		printf("no_chain_num:%d\n",no_chain_num);
		fprintf(fpWrite,"no_chain_num:%d\n",no_chain_num);
		printf("more_chain_num:%d\n",more_chain_num);
		fprintf(fpWrite,"more_chain_num:%d\n",more_chain_num);
		printf("match_four_num:%d\n",match_four_num);
		fprintf(fpWrite,"match_four_num:%d\n",match_four_num);
		printf("invalid_error_num:%d\n",invalid_error_num);
		fprintf(fpWrite,"invalid_error_num:%d\n",invalid_error_num);
		fclose(fpWrite);
	}
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
	FILE *fpWrite = fopen("experiment.txt", "a+");
	printf("\n总实验次数:%d\n",Experment_num);
	fprintf(fpWrite,"\n总实验次数:%d\n",Experment_num);
	printf("share个数:%d\n",n);
	fprintf(fpWrite,"share个数:%d\n",n);
	printf("平均需要加密%d次才能找到16个字节。\n最多需要%d次，最少需要%d次。\n",sum/Experment_num,max,min);
	fprintf(fpWrite,"平均需要加密%d次才能找到16个字节。\n最多需要%d次，最少需要%d次。\n",sum/Experment_num,max,min);
	printf("success_num:%d\n",success_num);
	fprintf(fpWrite,"success_num:%d\n",success_num);
	printf("fail_num:%d\n",fail_num);
	fprintf(fpWrite,"fail_num:%d\n",fail_num);
	printf("out_time_num:%d\n",out_time_num);
	fprintf(fpWrite,"out_time_num:%d\n",out_time_num);
	printf("no_chain_num:%d\n",no_chain_num);
	fprintf(fpWrite,"no_chain_num:%d\n",no_chain_num);
	printf("more_chain_num:%d\n",more_chain_num);
	fprintf(fpWrite,"more_chain_num:%d\n",more_chain_num);
	printf("match_four_num:%d\n",match_four_num);
	fprintf(fpWrite,"match_four_num:%d\n",match_four_num);
	printf("invalid_error_num:%d\n",invalid_error_num);
	fprintf(fpWrite,"invalid_error_num:%d\n",invalid_error_num);
	finish = clock(); 
	duration = (double)(finish - start) / CLOCKS_PER_SEC;  
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


