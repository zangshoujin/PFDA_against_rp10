// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License version 2 as published
// by the Free Software Foundation.
#define NOLOC 0
#define LOC 1
#include "aes_share.h"
#include "share.h"
#include "aes.h"
#include "prg.h"
#include "prgmat.h"
#include "aes_rp_prg.h"

#include <stdlib.h>
#include <stdio.h>
#include <time.h>

void print_state(byte *stateshare[16],int n,int round){
  printf("第%d轮:--share----------\n",round);
  
  for(int i=0;i<16;i++){
    for(int p=0;p<n;p++){
      printf("%02x",stateshare[i][p]);
    }
    printf("\t");
    if((i+1)%4== 0)printf("\n");
  }
  printf("\n");
}

int write_state(byte *encrypt_state[16],int n,int round, char *c) {
	FILE *fpWrite = fopen("encrypt_state.txt", "a+");
	if (fpWrite == NULL) {
		printf("encrypt_state文件不存在\n");
		getchar();
		return 0;
	}
  fprintf(fpWrite,"第%d轮:--%s----------\n",round,c);
	for(int i=0;i<16;i++){
    for(int p=0;p<n;p++){
      fprintf(fpWrite,"%02x",encrypt_state[i][p]);
    }
    fprintf(fpWrite,"\t");
    if((i+1)%4== 0)fprintf(fpWrite,"\n");
  }
  fprintf(fpWrite,"----------\n");
  for(int i=0;i<16;i++){
    fprintf(fpWrite,"%02x",decode(encrypt_state[i],n));
    if((i+1)%4== 0)fprintf(fpWrite,"\n");
  }
  fprintf(fpWrite,"\n");
	//printf("状态矩阵写入成功！\n");
	fclose(fpWrite);
	return 0;
}

void shiftrows_share(byte *stateshare[16],int n)
{
  byte m;
  int i;
  for(i=0;i<n;i++)
  {
    m=stateshare[1][i];
    stateshare[1][i]=stateshare[5][i];
    stateshare[5][i]=stateshare[9][i];
    stateshare[9][i]=stateshare[13][i];
    stateshare[13][i]=m;

    m=stateshare[2][i];
    stateshare[2][i]=stateshare[10][i];
    stateshare[10][i]=m;
    m=stateshare[6][i];
    stateshare[6][i]=stateshare[14][i];
    stateshare[14][i]=m;

    m=stateshare[3][i];
    stateshare[3][i]=stateshare[15][i];
    stateshare[15][i]=stateshare[11][i];
    stateshare[11][i]=stateshare[7][i];
    stateshare[7][i]=m;
  }
}

void mixcolumns_share(byte *stateshare[16],int n)
{
  byte ns[16];
  int i,j;
  for(i=0;i<n;i++)
  {
    for(j=0;j<4;j++)
    {
      ns[j*4]=multx(stateshare[j*4][i]) ^ multx(stateshare[j*4+1][i]) ^ stateshare[j*4+1][i] ^ stateshare[j*4+2][i] ^ stateshare[j*4+3][i];
      ns[j*4+1]=stateshare[j*4][i] ^ multx(stateshare[j*4+1][i]) ^ multx(stateshare[j*4+2][i]) ^ stateshare[j*4+2][i] ^ stateshare[j*4+3][i];
      ns[j*4+2]=stateshare[j*4][i] ^ stateshare[j*4+1][i] ^ multx(stateshare[j*4+2][i]) ^ multx(stateshare[j*4+3][i]) ^ stateshare[j*4+3][i];
      ns[j*4+3]=multx(stateshare[j*4][i]) ^ stateshare[j*4][i] ^ stateshare[j*4+1][i] ^ stateshare[j*4+2][i] ^ multx(stateshare[j*4+3][i]) ;
    }
    for(j=0;j<16;j++)
      stateshare[j][i]=ns[j];
  }
}

void mixcolumns_share_loc(byte *stateshare[16],int n)
{
  for(int j=0;j<4;j++)
  {
    byte ns[4][n];
    
    xor_loc32(stateshare[j*4+1],stateshare[j*4],ns[0],n);
    xor_loc(ns[0],stateshare[j*4+2],ns[0],n);
    xor_loc(ns[0],stateshare[j*4+3],ns[0],n);

    xor_loc32(stateshare[j*4+2],stateshare[j*4+1],ns[1],n);
    xor_loc(ns[1],stateshare[j*4],ns[1],n);
    xor_loc(ns[1],stateshare[j*4+3],ns[1],n);

    xor_loc32(stateshare[j*4+3],stateshare[j*4+2],ns[2],n);
    xor_loc(ns[2],stateshare[j*4],ns[2],n);
    xor_loc(ns[2],stateshare[j*4+1],ns[2],n);

    xor_loc32(stateshare[j*4],stateshare[j*4+3],ns[3],n);
    xor_loc(ns[3],stateshare[j*4+1],ns[3],n);
    xor_loc(ns[3],stateshare[j*4+2],ns[3],n);

    for(int i=0;i<n;i++)
    {  
      for(int k=0;k<4;k++)
	stateshare[j*4+k][i]=ns[k][i];
    }
  }
}

void addroundkey_share(byte *stateshare[16],byte *wshare[176],int round,int n)
{
  int i,j;
  for(i=0;i<16;i++)
    for(j=0;j<n;j++)
      stateshare[i][j]^=wshare[16*round+i][j];
}
 
void subbytestate_share(byte *stateshare[16],int n,void (*subbyte_share_call)(byte *,int))
{
  for(int i=0;i<16;i++){//一个中间状态字节->n个shares
    subbyte_share_call(stateshare[i],n);
  }
}

void subbytestate_share_no_error(byte *stateshare[16],int n,void (*subbyte_share_call)(byte *,int))
{
  for(int i=0;i<16;i++){//一个中间状态字节->n个shares
    subbyte_share_call(stateshare[i],n);
  }
} 

void subbytestate_share_no_error_print(byte *stateshare[16],int n,void (*subbyte_share_call)(byte *,int))
{
  for(int i=0;i<16;i++){//一个中间状态字节->n个shares
    subbyte_share_call(stateshare[i],n);
  }
} 


void subbytestate_share_print(byte *stateshare[16],int n,void (*subbyte_share_call)(byte *,int))
{
  for(int i=0;i<16;i++){//一个中间状态字节->n个shares
    FILE *fpWrite = fopen("encrypt_state.txt", "a+");
    subbyte_share_call(stateshare[i],n);
    if((i+1)%4 == 0) fprintf(fpWrite,"\n");
    fclose(fpWrite);
  }
  FILE *fpWrite = fopen("encrypt_state.txt", "a+");
  fprintf(fpWrite,"\n");
  fclose(fpWrite);
} 

// AES with shares. The subbyte computation with shares is given as parameter
void aes_share_subkeys(byte in[16],byte out[16],byte *wshare[176],int n,void (*subbyte_share_call)(byte *,int),int loc)
{
  int i,j;
  int round=0;

  byte *stateshare[16];
  
  for(i=0;i<16;i++)
  {
    stateshare[i]=(byte*) malloc(n*sizeof(byte));
    share(in[i], stateshare[i],n);
  }  
  addroundkey_share(stateshare,wshare,0,n);

  for(round=1;round<10;round++){ 
    subbytestate_share(stateshare,n,subbyte_share_call);
    shiftrows_share(stateshare,n);
    if (loc==NOLOC)        //???0 == 0 只有列混合，没有轮密钥加？
      mixcolumns_share(stateshare,n);
    else
      mixcolumns_share_loc(stateshare,n);
    addroundkey_share(stateshare,wshare,round,n);
  }
  subbytestate_share(stateshare,n,subbyte_share_call);
  shiftrows_share(stateshare,n);
  addroundkey_share(stateshare,wshare,10,n);
  for(i=0;i<16;i++){
    out[i]=decode(stateshare[i],n);
    free(stateshare[i]);
  }
}

// AES with shares. The subbyte computation with shares is given as parameter
void aes_share_subkeys_no_error(byte in[16],byte out[16],byte *wshare[176],int n,void (*subbyte_share_call)(byte *,int),int loc)
{
  int i,j;
  int round=0;

  byte *stateshare[16];

  for(i=0;i<16;i++)
  {
    stateshare[i]=(byte*) malloc(n*sizeof(byte));
    share(in[i], stateshare[i],n);
  }  
  addroundkey_share(stateshare,wshare,0,n);

  for(round=1;round<10;round++){ 
    subbytestate_share_no_error(stateshare,n,subbyte_share_call);
    shiftrows_share(stateshare,n);
    if (loc==NOLOC)         //???0 == 0 只有列混合，没有轮密钥加？
      mixcolumns_share(stateshare,n);
    
    else
      mixcolumns_share_loc(stateshare,n);
      addroundkey_share(stateshare,wshare,round,n);
    
  }
  subbytestate_share_no_error(stateshare,n,subbyte_share_call);
  shiftrows_share(stateshare,n);
  addroundkey_share(stateshare,wshare,10,n);
  for(i=0;i<16;i++){
    out[i]=decode(stateshare[i],n);
    free(stateshare[i]);
  }
}

// AES with shares. The subbyte computation with shares is given as parameter
void aes_share_subkeys_no_error_print(byte in[16],byte out[16],byte *wshare[176],int n,void (*subbyte_share_call)(byte *,int),int loc)
{
  int i,j;
  int round=0;

  byte *stateshare[16];

  for(i=0;i<16;i++)
  {
    stateshare[i]=(byte*) malloc(n*sizeof(byte));
    share(in[i], stateshare[i],n);
  }  
  write_state(stateshare,n,round,"明文");
  addroundkey_share(stateshare,wshare,0,n);

  for(round=1;round<10;round++){ 
    write_state(stateshare,n,round,"字节代换前");
    subbytestate_share_no_error_print(stateshare,n,subbyte_share_call);
    write_state(stateshare,n,round,"行移位前");
    shiftrows_share(stateshare,n);
    if (loc==NOLOC){         //???0 == 0 只有列混合，没有轮密钥加？
      write_state(stateshare,n,round,"列混合前：");
      mixcolumns_share(stateshare,n);
    }
    else{
      write_state(stateshare,n,round,"列混合前");
      mixcolumns_share_loc(stateshare,n);
      write_state(stateshare,n,round,"轮密钥加前");
      addroundkey_share(stateshare,wshare,round,n);
    }
  }
  write_state(stateshare,n,round,"字节代换前");
  subbytestate_share_no_error_print(stateshare,n,subbyte_share_call);
  write_state(stateshare,n,round,"行移位前");
  shiftrows_share(stateshare,n);
  write_state(stateshare,n,round,"轮密钥加前");
  addroundkey_share(stateshare,wshare,10,n);
  write_state(stateshare,n,round,"最终密文");
  for(i=0;i<16;i++){
    out[i]=decode(stateshare[i],n);
    free(stateshare[i]);
  }
}

// AES with shares. The subbyte computation with shares is given as parameter
void aes_share_subkeys_print(byte in[16],byte out[16],byte *wshare[176],int n,void (*subbyte_share_call)(byte *,int),int loc)
{
  int i,j;
  int round=0;

  byte *stateshare[16];

  for(i=0;i<16;i++)
  {
    stateshare[i]=(byte*) malloc(n*sizeof(byte));
    share(in[i], stateshare[i],n);
  }  
  write_state(stateshare,n,round,"明文");
  addroundkey_share(stateshare,wshare,0,n);

  for(round=1;round<10;round++){ 
    //print_state(stateshare,n,round);
    write_state(stateshare,n,round,"字节代换前");
    subbytestate_share_print(stateshare,n,subbyte_share_call);
    write_state(stateshare,n,round,"行移位前");
    shiftrows_share(stateshare,n);
    if (loc==NOLOC){         //???0 == 0 只有列混合，没有轮密钥加？
      write_state(stateshare,n,round,"列混合前：");
      mixcolumns_share(stateshare,n);
    }
    else{
      write_state(stateshare,n,round,"列混合前");
      mixcolumns_share_loc(stateshare,n);
      write_state(stateshare,n,round,"轮密钥加前");
      addroundkey_share(stateshare,wshare,round,n);
    }
  }
  
  // printf("第九轮结束的share：**************-------------***************/---------------\n");
  // for(int k=0;k<n;k++){
  // 	for(i=0;i<16;i++){
  //   	printf("%02x",stateshare[k][i]);
  //   	if((i+1)%4== 0)printf("\n");
  // 	}
  // 	printf("\n");
  // }
  // printf("\n");
  
  // printf("第九轮结束**************-------------***************/---------------\n");
  // for(i=0;i<16;i++){
  //   printf("%02x",decode(stateshare[i],n));
  //   if((i+1)%4== 0)printf("\n");
  // }
  // printf("\n");
  
  //print_state(stateshare,n,round);
  write_state(stateshare,n,round,"字节代换前");
  subbytestate_share_print(stateshare,n,subbyte_share_call);
  // printf("第十轮字节代换：**************-------------***************/---------------\n");
  // for(i=0;i<16;i++){
  //   printf("%02x",decode(stateshare[i],n));
  //   if((i+1)%4== 0)printf("\n");
  // }
  // printf("\n");
  write_state(stateshare,n,round,"行移位前");
  shiftrows_share(stateshare,n);
  // printf("第十轮行移位：**************-------------***************/---------------\n");
  // for(i=0;i<16;i++){
  //   printf("%02x",decode(stateshare[i],n));
  //   if((i+1)%4== 0)printf("\n");
  // }
  // printf("\n");
  write_state(stateshare,n,round,"轮密钥加前");
  addroundkey_share(stateshare,wshare,10,n);

  // printf("第十轮轮密钥:--share----------\n");
  
  // for(i=0;i<16;i++){
  //   for(int p=0;p<n;p++){
  //     printf("%02x",wshare[16*10+i][p]);
  //   }
  //   printf("\t");
  //   if((i+1)%4== 0)printf("\n");
  // }
  // printf("\n");

  // printf("第十轮轮密钥:------------\n");
  // for(i=0;i<16;i++){
  //   printf("%02x",decode(wshare[160+i],n));
  //   if((i+1)%4== 0)printf("\n");
  // }
  // printf("\n");
  write_state(stateshare,n,round,"最终密文");
  for(i=0;i<16;i++){
    out[i]=decode(stateshare[i],n);
    free(stateshare[i]);
  }
}

void keyexpansion_share(byte key[16],byte *wshare[176],int n)
{
  byte w[176];
  keyexpansion(key,w);

  int randc=get_randcount();
  for(int i=0;i<176;i++)
  {
    wshare[i]=(byte *) malloc(n*sizeof(byte));
    share(w[i],wshare[i],n);//wshare[0] = w[0], wshare[1....n] = 0,
    refresh(wshare[i],n);
  }
  set_randcount(randc);
}

void keyexpansion_share_no_error(byte key[16],byte *wshare[176],int n)
{
  byte w[176];
  keyexpansion(key,w);

  int randc=get_randcount();
  for(int i=0;i<176;i++)
  {
    wshare[i]=(byte *) malloc(n*sizeof(byte));
    share(w[i],wshare[i],n);//wshare[0] = w[0], wshare[1....n] = 0,
    refresh(wshare[i],n);
  }
  set_randcount(randc);
}

int run_aes_share(byte in[16],byte out[16],byte key[16],byte outex[16],int n,void (*subbyte_share_call)(byte *,int),int nt,int base)
{

  byte *wshare[176];

  keyexpansion_share(key,wshare,n);//使用share技术进行密钥扩展

  init_randcount();//初始化使用随机次数为0 
  clock_t start=clock();
  for(int i=0;i<1;i++)//这里原来i<nt,即nt<10,作者为了测试时间用
    aes_share_subkeys(in,out,wshare,n,subbyte_share_call,NOLOC);//加密轮函数
  clock_t end=clock();

  for(int i=0;i<176;i++)
    free(wshare[i]);
  int dt= (int) (end-start);//dt = 一次加密运行时间
  return dt;
}

int run_aes_share_no_error(byte in[16],byte out[16],byte key[16],byte outex[16],int n,void (*subbyte_share_call)(byte *,int),int nt,int base)
{
  byte *wshare[176];

  keyexpansion_share_no_error(key,wshare,n);//使用share技术进行密钥扩展

  init_randcount();//初始化使用随机次数为0 
  clock_t start=clock();

  for(int i=0;i<1;i++)//这里原来i<nt,即nt<10,作者为了测试时间用
    aes_share_subkeys_no_error(in,out,wshare,n,subbyte_share_call,NOLOC);//加密轮函数
  clock_t end=clock();

  for(int i=0;i<176;i++)
    free(wshare[i]);

  int dt= (int) (end-start);//dt = 一次加密运行时间
  return dt;
}

int run_aes_share_no_error_print(byte in[16],byte out[16],byte key[16],byte outex[16],int n,void (*subbyte_share_call)(byte *,int),int nt,int base)
{
  byte *wshare[176];

  keyexpansion_share_no_error(key,wshare,n);//使用share技术进行密钥扩展

  init_randcount();//初始化使用随机次数为0 
  clock_t start=clock();

  for(int i=0;i<1;i++)//这里原来i<nt,即nt<10,作者为了测试时间用
    aes_share_subkeys_no_error_print(in,out,wshare,n,subbyte_share_call,NOLOC);//加密轮函数
  clock_t end=clock();

  for(int i=0;i<176;i++)
    free(wshare[i]);

  int dt= (int) (end-start);//dt = 一次加密运行时间
  return dt;
}

int run_aes_share_print(byte in[16],byte out[16],byte key[16],byte outex[16],int n,void (*subbyte_share_call)(byte *,int),int nt,int base){
  byte *wshare[176];

  keyexpansion_share(key,wshare,n);//使用share技术进行密钥扩展
  // for(int i=159;i<176;i++){
  //   printf("%02x",decode(wshare[i],n));
  //   if((i+1)%4 == 0)printf("\n");
  //   if((i+1)%16 == 0)printf("\n");
  // }
  init_randcount();//初始化使用随机次数为0 
  clock_t start=clock();

  for(int i=0;i<1;i++)//这里原来i<nt,即nt<10,作者为了测试时间用
    aes_share_subkeys_print(in,out,wshare,n,subbyte_share_call,NOLOC);//加密轮函数
  clock_t end=clock();

  for(int i=0;i<176;i++)
    free(wshare[i]);

  int dt= (int) (end-start);//dt = 一次加密运行时间
  //report_time(dt,nt,base,get_randcount()); //打印计算耗时
  //check_ciphertext(out,outex,16);//检查密文是否正确
  return dt;
}

int run_aes_share_prg(byte in[16],byte out[16],byte key[16],byte *outex,int n,void (*subbyte_share_call)(byte *,int),int base,int nt,int rprg)
{
  byte *wshare[176];
  int prgcount;

  keyexpansion_share(key,wshare,n);

  init_randcount();
  clock_t start=clock();
  for(int i=0;i<nt;i++)
  {
    init_robprg(rprg,n);
    aes_share_subkeys(in,out,wshare,n,subbyte_share_call,NOLOC);
    prgcount=get_robprgcount();
    free_robprg(n);
  }
  clock_t end=clock();
  
  for(int i=0;i<176;i++)
    free(wshare[i]);

  int dt=(int) end-start;
  report_time(dt,nt,base,get_randcount());
  //check_ciphertext(out,outex,16);
  //printf(" rprg=%d  prgcount=%d ",rprg,prgcount);

  return dt;
}

int run_aes_share_mprg(byte in[16],byte out[16],byte key[16],byte *outex,int n,void (*subbyte_share_call)(byte *,int),int type,int base,int nt)
{
  byte *wshare[176];

  keyexpansion_share(key,wshare,n);

  init_randcount();
  clock_t start=clock();

  int loc,rc,ni,ri;
  loc=5;
  rc=loc*(n-1);

  if(type==TFLR)
  {
    ni=n*(n-1)/2;
    ri=n-1;
  } else
  {
    ni=n-1;
    ri=n-1;
  }

  for(int i=0;i<nt;i++)
  {
    init_mprg(rc,ni,ri,n);
    aes_share_subkeys(in,out,wshare,n,subbyte_share_call,NOLOC);
    free_mprg(ni,n);
  }
  clock_t end=clock();
  
  for(int i=0;i<176;i++)
    free(wshare[i]);

  int dt=(int) end-start;
  report_time(dt,nt,base,get_randcount());
  //check_ciphertext(out,outex,16);
  printf(" randc=%d randi=%d tot=%d",rc*(n-1),ri*ni,(rc*(n-1)+ri*ni)*2);
  printf(" prgcount=%d ",get_mprgcount());

  return dt;
}

int run_aes_share_mprgmat(byte in[16],byte out[16],byte key[16],byte *outex,int n,int base,int nt)
{
  byte *wshare[176];
  keyexpansion_share(key,wshare,n);
  init_randcount();
  clock_t start=clock();

  int ni=n*(n-1)/2;
  int dmax=1000;
  for(int i=0;i<nt;i++)
  {
    init_mprgmat(ni,n,dmax);
    aes_share_subkeys(in,out,wshare,n,subbyte_rp_share_flr_mprgmat,LOC);
    free_mprgmat(ni,n);
  }
  clock_t end=clock();
  
  for(int i=0;i<176;i++)
    free(wshare[i]);

  int dt=(int) end-start;
  report_time(dt,nt,base,get_randcount());
  //check_ciphertext(out,outex,16);
  return dt;
}

void subbytestate_common_share(byte *stateshare[16],int n,void (*subbyte_common_share_call)(byte *,byte *,int))
{
  int i;
  for(i=0;i<16;i+=2)
    subbyte_common_share_call(stateshare[i],stateshare[i+1],n);
} 

// AES with shares. The subbyte computation with shares is given as parameter
void aes_common_share_subkeys(byte in[16],byte out[16],byte *wshare[176],int n,void (*subbyte_common_share_call)(byte *,byte *,int))
{
  int i,j;
  int round=0;

  byte *stateshare[16];

  for(i=0;i<16;i++)
  {
    stateshare[i]=(byte*) malloc(n*sizeof(byte));
    share(in[i],stateshare[i],n);
    refresh(stateshare[i],n);
  }  

  addroundkey_share(stateshare,wshare,0,n);

  for(round=1;round<10;round++)
  { 
    subbytestate_common_share(stateshare,n,subbyte_common_share_call);
    shiftrows_share(stateshare,n);
    mixcolumns_share(stateshare,n);
    addroundkey_share(stateshare,wshare,round,n);
  }
 
  subbytestate_common_share(stateshare,n,subbyte_common_share_call);
  shiftrows_share(stateshare,n);
  addroundkey_share(stateshare,wshare,10,n);

  for(i=0;i<16;i++)
  {
    out[i]=decode(stateshare[i],n);
    free(stateshare[i]);
  }
}

int run_aes_common_share(byte in[16],byte out[16],byte key[16],byte outex[16],int n,void (*subbyte_common_share_call)(byte *,byte *,int),int base,int nt)
{
  int i;
  byte *wshare[176];
  clock_t start,end;

  keyexpansion_share(key,wshare,n);

  init_randcount();
  
  start=clock();
  for(i=0;i<nt;i++)
    aes_common_share_subkeys(in,out,wshare,n,subbyte_common_share_call);
  end=clock();

  for(i=0;i<176;i++)
    free(wshare[i]);

  int dt=(int) (end-start);
  report_time(dt,nt,base,get_randcount());
  //check_ciphertext(out,outex,16);    
  
  return dt;
}
  

