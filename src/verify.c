#include "verify.h"
#include "time.h"

int verify_offline_key(byte guess_key_10round[16][16],byte w[176],int candidiate_key_count[16],
	int* success_num,int* fail_num,byte cipher_verify[16],byte in[16],int n,int nt,int base,byte reall_main_key[16],
	int *timeout_num,int *other_fail_num){
	clock_t start,middle;
	start = clock();
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
																	middle = clock();
																	if((double)(middle-start)/CLOCKS_PER_SEC >= 3660.0){
																		/*
																			2的30次方1073741824  
																			2的20次方1048576
																			2的22次方4194304
																			2的23次方8388608，超时时间大约是不到500秒
																			2的25次方33554432 理论上这个的超时时间应该是1800秒
																		*/
																		(*timeout_num)++;
																		FILE *fpWrite = fopen("experiment.txt", "a+");
																		printf("超时超时！一共验证了%d个候选密钥\n",verify_encrypt_num);
																		fprintf(fpWrite,"超时超时！一共验证了%d个候选密钥\n",verify_encrypt_num);
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
																	recovery_main_key(guess_key,guess_main_key);//这个是没有错误的逆密钥扩展
																	byte w[176];
																	keyexpansion(guess_main_key,w);
																	aes(in,out,w);
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
																			for(int y=0;y<16;y++){
																				printf("%02x,",guess_key[y]);
																				fprintf(fpWrite,"%02x,",guess_key[y]);
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
																			return 1;
																		}
																		else{
																			(*other_fail_num)++;
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
