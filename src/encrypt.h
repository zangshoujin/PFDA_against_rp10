#ifndef __encrypt_h__
#define __encrypt_h__

#include "recovery.h"
#include "aes_rp.h"
#include <stdio.h>
#include "aes_share.h"
#include "print.h"
#include "filter.h"

typedef unsigned char byte;
typedef int bool;
#define true 1
#define false 0
#define Cipher_num 1000

#define Experment_num 10
#define Share_num 2
#define Is_random 1  //控制是否随机明文、密钥和错误,调试用 1:表示随机 0:表示固定
#define Is_print 1 //控制是否打印详细数据，1:表示打印，0:表示不打印

int encrypt_find_different(byte in[16],byte out[16],byte key[16],byte outex[16],int n,int nt,int base,byte* delta,
	byte differential_cipher_4_error[4][4],struct Different_Cipher dc[4],int relationship_delta_difference_cipher[4][4],
	int diff_delta_count[4],int* appear_4_but_not_match,int* no_chain,int* more_chain,int* match_four,byte cipher_verify[16]);


/*
int encrypt_find_different_dynamic_array(byte in[16],byte out[16],byte key[16],
	byte outex[16],int n,int nt,int base,byte* delta,byte differential_cipher_4_error[4][4]);
*/

#endif