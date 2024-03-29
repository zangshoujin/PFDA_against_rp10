// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License version 2 as published
// by the Free Software Foundation.

#include "aes_rp.h"
#include "share.h"
#include "aes.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

byte sq[256]={
0x00,0x01,0x04,0x05,0x10,0x11,0x14,0x15,
0x40,0x41,0x44,0x45,0x50,0x51,0x54,0x55,
0x1b,0x1a,0x1f,0x1e,0x0b,0x0a,0x0f,0x0e,
0x5b,0x5a,0x5f,0x5e,0x4b,0x4a,0x4f,0x4e,
0x6c,0x6d,0x68,0x69,0x7c,0x7d,0x78,0x79,
0x2c,0x2d,0x28,0x29,0x3c,0x3d,0x38,0x39,
0x77,0x76,0x73,0x72,0x67,0x66,0x63,0x62,
0x37,0x36,0x33,0x32,0x27,0x26,0x23,0x22,
0xab,0xaa,0xaf,0xae,0xbb,0xba,0xbf,0xbe,
0xeb,0xea,0xef,0xee,0xfb,0xfa,0xff,0xfe,
0xb0,0xb1,0xb4,0xb5,0xa0,0xa1,0xa4,0xa5,
0xf0,0xf1,0xf4,0xf5,0xe0,0xe1,0xe4,0xe5,
0xc7,0xc6,0xc3,0xc2,0xd7,0xd6,0xd3,0xd2,
0x87,0x86,0x83,0x82,0x97,0x96,0x93,0x92,
0xdc,0xdd,0xd8,0xd9,0xcc,0xcd,0xc8,0xc9,
0x9c,0x9d,0x98,0x99,0x8c,0x8d,0x88,0x89,
0x9a,0x9b,0x9e,0x9f,0x8a,0x8b,0x8e,0x8f,
0xda,0xdb,0xde,0xdf,0xca,0xcb,0xce,0xcf,
0x81,0x80,0x85,0x84,0x91,0x90,0x95,0x94,
0xc1,0xc0,0xc5,0xc4,0xd1,0xd0,0xd5,0xd4,
0xf6,0xf7,0xf2,0xf3,0xe6,0xe7,0xe2,0xe3,
0xb6,0xb7,0xb2,0xb3,0xa6,0xa7,0xa2,0xa3,
0xed,0xec,0xe9,0xe8,0xfd,0xfc,0xf9,0xf8,
0xad,0xac,0xa9,0xa8,0xbd,0xbc,0xb9,0xb8,
0x31,0x30,0x35,0x34,0x21,0x20,0x25,0x24,
0x71,0x70,0x75,0x74,0x61,0x60,0x65,0x64,
0x2a,0x2b,0x2e,0x2f,0x3a,0x3b,0x3e,0x3f,
0x6a,0x6b,0x6e,0x6f,0x7a,0x7b,0x7e,0x7f,
0x5d,0x5c,0x59,0x58,0x4d,0x4c,0x49,0x48,
0x1d,0x1c,0x19,0x18,0x0d,0x0c,0x09,0x08,
0x46,0x47,0x42,0x43,0x56,0x57,0x52,0x53,
0x06,0x07,0x02,0x03,0x16,0x17,0x12,0x13};

byte taffine[256]={
0x63,0x7c,0x5d,0x42,0x1f,0x00,0x21,0x3e,
0x9b,0x84,0xa5,0xba,0xe7,0xf8,0xd9,0xc6,
0x92,0x8d,0xac,0xb3,0xee,0xf1,0xd0,0xcf,
0x6a,0x75,0x54,0x4b,0x16,0x09,0x28,0x37,
0x80,0x9f,0xbe,0xa1,0xfc,0xe3,0xc2,0xdd,
0x78,0x67,0x46,0x59,0x04,0x1b,0x3a,0x25,
0x71,0x6e,0x4f,0x50,0x0d,0x12,0x33,0x2c,
0x89,0x96,0xb7,0xa8,0xf5,0xea,0xcb,0xd4,
0xa4,0xbb,0x9a,0x85,0xd8,0xc7,0xe6,0xf9,
0x5c,0x43,0x62,0x7d,0x20,0x3f,0x1e,0x01,
0x55,0x4a,0x6b,0x74,0x29,0x36,0x17,0x08,
0xad,0xb2,0x93,0x8c,0xd1,0xce,0xef,0xf0,
0x47,0x58,0x79,0x66,0x3b,0x24,0x05,0x1a,
0xbf,0xa0,0x81,0x9e,0xc3,0xdc,0xfd,0xe2,
0xb6,0xa9,0x88,0x97,0xca,0xd5,0xf4,0xeb,
0x4e,0x51,0x70,0x6f,0x32,0x2d,0x0c,0x13,
0xec,0xf3,0xd2,0xcd,0x90,0x8f,0xae,0xb1,
0x14,0x0b,0x2a,0x35,0x68,0x77,0x56,0x49,
0x1d,0x02,0x23,0x3c,0x61,0x7e,0x5f,0x40,
0xe5,0xfa,0xdb,0xc4,0x99,0x86,0xa7,0xb8,
0x0f,0x10,0x31,0x2e,0x73,0x6c,0x4d,0x52,
0xf7,0xe8,0xc9,0xd6,0x8b,0x94,0xb5,0xaa,
0xfe,0xe1,0xc0,0xdf,0x82,0x9d,0xbc,0xa3,
0x06,0x19,0x38,0x27,0x7a,0x65,0x44,0x5b,
0x2b,0x34,0x15,0x0a,0x57,0x48,0x69,0x76,
0xd3,0xcc,0xed,0xf2,0xaf,0xb0,0x91,0x8e,
0xda,0xc5,0xe4,0xfb,0xa6,0xb9,0x98,0x87,
0x22,0x3d,0x1c,0x03,0x5e,0x41,0x60,0x7f,
0xc8,0xd7,0xf6,0xe9,0xb4,0xab,0x8a,0x95,
0x30,0x2f,0x0e,0x11,0x4c,0x53,0x72,0x6d,
0x39,0x26,0x07,0x18,0x45,0x5a,0x7b,0x64,
0xc1,0xde,0xff,0xe0,0xbd,0xa2,0x83,0x9c};

byte taffine_no_error[256]={
0x63,0x7c,0x5d,0x42,0x1f,0x00,0x21,0x3e,
0x9b,0x84,0xa5,0xba,0xe7,0xf8,0xd9,0xc6,
0x92,0x8d,0xac,0xb3,0xee,0xf1,0xd0,0xcf,
0x6a,0x75,0x54,0x4b,0x16,0x09,0x28,0x37,
0x80,0x9f,0xbe,0xa1,0xfc,0xe3,0xc2,0xdd,
0x78,0x67,0x46,0x59,0x04,0x1b,0x3a,0x25,
0x71,0x6e,0x4f,0x50,0x0d,0x12,0x33,0x2c,
0x89,0x96,0xb7,0xa8,0xf5,0xea,0xcb,0xd4,
0xa4,0xbb,0x9a,0x85,0xd8,0xc7,0xe6,0xf9,
0x5c,0x43,0x62,0x7d,0x20,0x3f,0x1e,0x01,
0x55,0x4a,0x6b,0x74,0x29,0x36,0x17,0x08,
0xad,0xb2,0x93,0x8c,0xd1,0xce,0xef,0xf0,
0x47,0x58,0x79,0x66,0x3b,0x24,0x05,0x1a,
0xbf,0xa0,0x81,0x9e,0xc3,0xdc,0xfd,0xe2,
0xb6,0xa9,0x88,0x97,0xca,0xd5,0xf4,0xeb,
0x4e,0x51,0x70,0x6f,0x32,0x2d,0x0c,0x13,
0xec,0xf3,0xd2,0xcd,0x90,0x8f,0xae,0xb1,
0x14,0x0b,0x2a,0x35,0x68,0x77,0x56,0x49,
0x1d,0x02,0x23,0x3c,0x61,0x7e,0x5f,0x40,
0xe5,0xfa,0xdb,0xc4,0x99,0x86,0xa7,0xb8,
0x0f,0x10,0x31,0x2e,0x73,0x6c,0x4d,0x52,
0xf7,0xe8,0xc9,0xd6,0x8b,0x94,0xb5,0xaa,
0xfe,0xe1,0xc0,0xdf,0x82,0x9d,0xbc,0xa3,
0x06,0x19,0x38,0x27,0x7a,0x65,0x44,0x5b,
0x2b,0x34,0x15,0x0a,0x57,0x48,0x69,0x76,
0xd3,0xcc,0xed,0xf2,0xaf,0xb0,0x91,0x8e,
0xda,0xc5,0xe4,0xfb,0xa6,0xb9,0x98,0x87,
0x22,0x3d,0x1c,0x03,0x5e,0x41,0x60,0x7f,
0xc8,0xd7,0xf6,0xe9,0xb4,0xab,0x8a,0x95,
0x30,0x2f,0x0e,0x11,0x4c,0x53,0x72,0x6d,
0x39,0x26,0x07,0x18,0x45,0x5a,0x7b,0x64,
0xc1,0xde,0xff,0xe0,0xbd,0xa2,0x83,0x9c};

byte taffine_copy[256]={
0x63,0x7c,0x5d,0x42,0x1f,0x00,0x21,0x3e,
0x9b,0x84,0xa5,0xba,0xe7,0xf8,0xd9,0xc6,
0x92,0x8d,0xac,0xb3,0xee,0xf1,0xd0,0xcf,
0x6a,0x75,0x54,0x4b,0x16,0x09,0x28,0x37,
0x80,0x9f,0xbe,0xa1,0xfc,0xe3,0xc2,0xdd,
0x78,0x67,0x46,0x59,0x04,0x1b,0x3a,0x25,
0x71,0x6e,0x4f,0x50,0x0d,0x12,0x33,0x2c,
0x89,0x96,0xb7,0xa8,0xf5,0xea,0xcb,0xd4,
0xa4,0xbb,0x9a,0x85,0xd8,0xc7,0xe6,0xf9,
0x5c,0x43,0x62,0x7d,0x20,0x3f,0x1e,0x01,
0x55,0x4a,0x6b,0x74,0x29,0x36,0x17,0x08,
0xad,0xb2,0x93,0x8c,0xd1,0xce,0xef,0xf0,
0x47,0x58,0x79,0x66,0x3b,0x24,0x05,0x1a,
0xbf,0xa0,0x81,0x9e,0xc3,0xdc,0xfd,0xe2,
0xb6,0xa9,0x88,0x97,0xca,0xd5,0xf4,0xeb,
0x4e,0x51,0x70,0x6f,0x32,0x2d,0x0c,0x13,
0xec,0xf3,0xd2,0xcd,0x90,0x8f,0xae,0xb1,
0x14,0x0b,0x2a,0x35,0x68,0x77,0x56,0x49,
0x1d,0x02,0x23,0x3c,0x61,0x7e,0x5f,0x40,
0xe5,0xfa,0xdb,0xc4,0x99,0x86,0xa7,0xb8,
0x0f,0x10,0x31,0x2e,0x73,0x6c,0x4d,0x52,
0xf7,0xe8,0xc9,0xd6,0x8b,0x94,0xb5,0xaa,
0xfe,0xe1,0xc0,0xdf,0x82,0x9d,0xbc,0xa3,
0x06,0x19,0x38,0x27,0x7a,0x65,0x44,0x5b,
0x2b,0x34,0x15,0x0a,0x57,0x48,0x69,0x76,
0xd3,0xcc,0xed,0xf2,0xaf,0xb0,0x91,0x8e,
0xda,0xc5,0xe4,0xfb,0xa6,0xb9,0x98,0x87,
0x22,0x3d,0x1c,0x03,0x5e,0x41,0x60,0x7f,
0xc8,0xd7,0xf6,0xe9,0xb4,0xab,0x8a,0x95,
0x30,0x2f,0x0e,0x11,0x4c,0x53,0x72,0x6d,
0x39,0x26,0x07,0x18,0x45,0x5a,0x7b,0x64,
0xc1,0xde,0xff,0xe0,0xbd,0xa2,0x83,0x9c};


/*byte taffine[256]={  
0x63,0x7c,0x5d,0x42,0x1f,0x00,0x21,0x3e,
0x9b,0x84,0xa5,0xba,0xe7,0xf8,0xd9,0xc6,
0x92,0x8d,0xac,0xb3,0xee,0xf1,0xd0,0xcf,
0x6a,0x75,0x54,0x4b,0x16,0x09,0x28,0x37,
0x80,0x9f,0xbe,0xa1,0xfc,0xe3,0xc2,0xdd,
0x78,0x67,0x46,0x59,0x04,0x1b,0x3a,0x25,
0x71,0x6e,0x4f,0x50,0x0d,0x12,0x33,0x2c,
0x89,0x96,0xb7,0xa8,0xf5,0xea,0xcb,0xd4,
0xa4,0xbb,0x9a,0x85,0xd8,0xc7,0xe6,0xf9,
0x5c,0x43,0x62,0x7d,0x20,0x3f,0x1e,0x01,
0x55,0x4a,0x6b,0x74,0x29,0x36,0x17,0x08,
0xad,0xb2,0x93,0x8c,0xd1,0xce,0xef,0xf0,
0x47,0x58,0x79,0x66,0x3b,0x24,0x05,0x1a,
0xbf,0xa0,0x81,0x9e,0xc3,0xdc,0xfd,0xe2,
0xb6,0xa9,0x88,0x97,0xca,0xd5,0xf4,0xeb,
0x4e,0x51,0x70,0x6f,0x32,0x2d,0x0c,0x13,
0xec,0xf3,0xd2,0xcd,0x90,0x8f,0xae,0xb1,
0x14,0x0b,0x2a,0x35,0x68,0x77,0x56,0x49,
0x1d,0x02,0x23,0x3c,0x61,0x7e,0x5f,0x40,
0xe5,0xfa,0xdb,0xc4,0x99,0x86,0xa7,0xb8,
0x0f,0x10,0x31,0x2e,0x73,0x6c,0x4d,0x52,
0xf7,0xe8,0xc9,0xd6,0x8b,0x94,0xb5,0xaa,
0xfe,0xe1,0xc0,0xdf,0x82,0x9d,0xbc,0xa3,
0x06,0x19,0x38,0x27,0x7a,0x65,0x44,0x5b,
0x2b,0x34,0x15,0x0a,0x57,0x48,0x69,0x76,
0xd3,0xcc,0xed,0xf2,0xaf,0xb0,0x91,0x8e,
0xda,0xc5,0xe4,0xfb,0xa6,0xb9,0x98,0x87,
0x22,0x3d,0x1c,0x03,0x5e,0x41,0x60,0x7f,
0xc8,0xd7,0xf6,0xe9,0xb4,0xab,0x8a,0x95,
0x30,0x2f,0x0e,0x11,0x4c,0x53,0x72,0x6d,
0x39,0x26,0x07,0x18,0x45,0x5a,0x7b,0x64,
0xc1,0xde,0xff,0xe0,0xbd,0xa2,0x83,0x9c};
*/ 


byte tsmult[1024]={
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
0x00,0x02,0x04,0x06,0x08,0x0a,0x0c,0x0e,
0x10,0x12,0x14,0x16,0x18,0x1a,0x1c,0x1e,
0x00,0x03,0x06,0x05,0x0c,0x0f,0x0a,0x09,
0x18,0x1b,0x1e,0x1d,0x14,0x17,0x12,0x11,
0x00,0x04,0x08,0x0c,0x10,0x14,0x18,0x1c,
0x20,0x24,0x28,0x2c,0x30,0x34,0x38,0x3c,
0x00,0x05,0x0a,0x0f,0x14,0x11,0x1e,0x1b,
0x28,0x2d,0x22,0x27,0x3c,0x39,0x36,0x33,
0x00,0x06,0x0c,0x0a,0x18,0x1e,0x14,0x12,
0x30,0x36,0x3c,0x3a,0x28,0x2e,0x24,0x22,
0x00,0x07,0x0e,0x09,0x1c,0x1b,0x12,0x15,
0x38,0x3f,0x36,0x31,0x24,0x23,0x2a,0x2d,
0x00,0x08,0x10,0x18,0x20,0x28,0x30,0x38,
0x40,0x48,0x50,0x58,0x60,0x68,0x70,0x78,
0x00,0x09,0x12,0x1b,0x24,0x2d,0x36,0x3f,
0x48,0x41,0x5a,0x53,0x6c,0x65,0x7e,0x77,
0x00,0x0a,0x14,0x1e,0x28,0x22,0x3c,0x36,
0x50,0x5a,0x44,0x4e,0x78,0x72,0x6c,0x66,
0x00,0x0b,0x16,0x1d,0x2c,0x27,0x3a,0x31,
0x58,0x53,0x4e,0x45,0x74,0x7f,0x62,0x69,
0x00,0x0c,0x18,0x14,0x30,0x3c,0x28,0x24,
0x60,0x6c,0x78,0x74,0x50,0x5c,0x48,0x44,
0x00,0x0d,0x1a,0x17,0x34,0x39,0x2e,0x23,
0x68,0x65,0x72,0x7f,0x5c,0x51,0x46,0x4b,
0x00,0x0e,0x1c,0x12,0x38,0x36,0x24,0x2a,
0x70,0x7e,0x6c,0x62,0x48,0x46,0x54,0x5a,
0x00,0x0f,0x1e,0x11,0x3c,0x33,0x22,0x2d,
0x78,0x77,0x66,0x69,0x44,0x4b,0x5a,0x55,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x10,0x20,0x30,0x40,0x50,0x60,0x70,
0x80,0x90,0xa0,0xb0,0xc0,0xd0,0xe0,0xf0,
0x00,0x20,0x40,0x60,0x80,0xa0,0xc0,0xe0,
0x1b,0x3b,0x5b,0x7b,0x9b,0xbb,0xdb,0xfb,
0x00,0x30,0x60,0x50,0xc0,0xf0,0xa0,0x90,
0x9b,0xab,0xfb,0xcb,0x5b,0x6b,0x3b,0x0b,
0x00,0x40,0x80,0xc0,0x1b,0x5b,0x9b,0xdb,
0x36,0x76,0xb6,0xf6,0x2d,0x6d,0xad,0xed,
0x00,0x50,0xa0,0xf0,0x5b,0x0b,0xfb,0xab,
0xb6,0xe6,0x16,0x46,0xed,0xbd,0x4d,0x1d,
0x00,0x60,0xc0,0xa0,0x9b,0xfb,0x5b,0x3b,
0x2d,0x4d,0xed,0x8d,0xb6,0xd6,0x76,0x16,
0x00,0x70,0xe0,0x90,0xdb,0xab,0x3b,0x4b,
0xad,0xdd,0x4d,0x3d,0x76,0x06,0x96,0xe6,
0x00,0x80,0x1b,0x9b,0x36,0xb6,0x2d,0xad,
0x6c,0xec,0x77,0xf7,0x5a,0xda,0x41,0xc1,
0x00,0x90,0x3b,0xab,0x76,0xe6,0x4d,0xdd,
0xec,0x7c,0xd7,0x47,0x9a,0x0a,0xa1,0x31,
0x00,0xa0,0x5b,0xfb,0xb6,0x16,0xed,0x4d,
0x77,0xd7,0x2c,0x8c,0xc1,0x61,0x9a,0x3a,
0x00,0xb0,0x7b,0xcb,0xf6,0x46,0x8d,0x3d,
0xf7,0x47,0x8c,0x3c,0x01,0xb1,0x7a,0xca,
0x00,0xc0,0x9b,0x5b,0x2d,0xed,0xb6,0x76,
0x5a,0x9a,0xc1,0x01,0x77,0xb7,0xec,0x2c,
0x00,0xd0,0xbb,0x6b,0x6d,0xbd,0xd6,0x06,
0xda,0x0a,0x61,0xb1,0xb7,0x67,0x0c,0xdc,
0x00,0xe0,0xdb,0x3b,0xad,0x4d,0x76,0x96,
0x41,0xa1,0x9a,0x7a,0xec,0x0c,0x37,0xd7,
0x00,0xf0,0xfb,0x0b,0xed,0x1d,0x16,0xe6,
0xc1,0x31,0x3a,0xca,0x2c,0xdc,0xd7,0x27,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x10,0x20,0x30,0x40,0x50,0x60,0x70,
0x80,0x90,0xa0,0xb0,0xc0,0xd0,0xe0,0xf0,
0x00,0x20,0x40,0x60,0x80,0xa0,0xc0,0xe0,
0x1b,0x3b,0x5b,0x7b,0x9b,0xbb,0xdb,0xfb,
0x00,0x30,0x60,0x50,0xc0,0xf0,0xa0,0x90,
0x9b,0xab,0xfb,0xcb,0x5b,0x6b,0x3b,0x0b,
0x00,0x40,0x80,0xc0,0x1b,0x5b,0x9b,0xdb,
0x36,0x76,0xb6,0xf6,0x2d,0x6d,0xad,0xed,
0x00,0x50,0xa0,0xf0,0x5b,0x0b,0xfb,0xab,
0xb6,0xe6,0x16,0x46,0xed,0xbd,0x4d,0x1d,
0x00,0x60,0xc0,0xa0,0x9b,0xfb,0x5b,0x3b,
0x2d,0x4d,0xed,0x8d,0xb6,0xd6,0x76,0x16,
0x00,0x70,0xe0,0x90,0xdb,0xab,0x3b,0x4b,
0xad,0xdd,0x4d,0x3d,0x76,0x06,0x96,0xe6,
0x00,0x80,0x1b,0x9b,0x36,0xb6,0x2d,0xad,
0x6c,0xec,0x77,0xf7,0x5a,0xda,0x41,0xc1,
0x00,0x90,0x3b,0xab,0x76,0xe6,0x4d,0xdd,
0xec,0x7c,0xd7,0x47,0x9a,0x0a,0xa1,0x31,
0x00,0xa0,0x5b,0xfb,0xb6,0x16,0xed,0x4d,
0x77,0xd7,0x2c,0x8c,0xc1,0x61,0x9a,0x3a,
0x00,0xb0,0x7b,0xcb,0xf6,0x46,0x8d,0x3d,
0xf7,0x47,0x8c,0x3c,0x01,0xb1,0x7a,0xca,
0x00,0xc0,0x9b,0x5b,0x2d,0xed,0xb6,0x76,
0x5a,0x9a,0xc1,0x01,0x77,0xb7,0xec,0x2c,
0x00,0xd0,0xbb,0x6b,0x6d,0xbd,0xd6,0x06,
0xda,0x0a,0x61,0xb1,0xb7,0x67,0x0c,0xdc,
0x00,0xe0,0xdb,0x3b,0xad,0x4d,0x76,0x96,
0x41,0xa1,0x9a,0x7a,0xec,0x0c,0x37,0xd7,
0x00,0xf0,0xfb,0x0b,0xed,0x1d,0x16,0xe6,
0xc1,0x31,0x3a,0xca,0x2c,0xdc,0xd7,0x27,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x1b,0x36,0x2d,0x6c,0x77,0x5a,0x41,
0xd8,0xc3,0xee,0xf5,0xb4,0xaf,0x82,0x99,
0x00,0x36,0x6c,0x5a,0xd8,0xee,0xb4,0x82,
0xab,0x9d,0xc7,0xf1,0x73,0x45,0x1f,0x29,
0x00,0x2d,0x5a,0x77,0xb4,0x99,0xee,0xc3,
0x73,0x5e,0x29,0x04,0xc7,0xea,0x9d,0xb0,
0x00,0x6c,0xd8,0xb4,0xab,0xc7,0x73,0x1f,
0x4d,0x21,0x95,0xf9,0xe6,0x8a,0x3e,0x52,
0x00,0x77,0xee,0x99,0xc7,0xb0,0x29,0x5e,
0x95,0xe2,0x7b,0x0c,0x52,0x25,0xbc,0xcb,
0x00,0x5a,0xb4,0xee,0x73,0x29,0xc7,0x9d,
0xe6,0xbc,0x52,0x08,0x95,0xcf,0x21,0x7b,
0x00,0x41,0x82,0xc3,0x1f,0x5e,0x9d,0xdc,
0x3e,0x7f,0xbc,0xfd,0x21,0x60,0xa3,0xe2,
0x00,0xd8,0xab,0x73,0x4d,0x95,0xe6,0x3e,
0x9a,0x42,0x31,0xe9,0xd7,0x0f,0x7c,0xa4,
0x00,0xc3,0x9d,0x5e,0x21,0xe2,0xbc,0x7f,
0x42,0x81,0xdf,0x1c,0x63,0xa0,0xfe,0x3d,
0x00,0xee,0xc7,0x29,0x95,0x7b,0x52,0xbc,
0x31,0xdf,0xf6,0x18,0xa4,0x4a,0x63,0x8d,
0x00,0xf5,0xf1,0x04,0xf9,0x0c,0x08,0xfd,
0xe9,0x1c,0x18,0xed,0x10,0xe5,0xe1,0x14,
0x00,0xb4,0x73,0xc7,0xe6,0x52,0x95,0x21,
0xd7,0x63,0xa4,0x10,0x31,0x85,0x42,0xf6,
0x00,0xaf,0x45,0xea,0x8a,0x25,0xcf,0x60,
0x0f,0xa0,0x4a,0xe5,0x85,0x2a,0xc0,0x6f,
0x00,0x82,0x1f,0x9d,0x3e,0xbc,0x21,0xa3,
0x7c,0xfe,0x63,0xe1,0x42,0xc0,0x5d,0xdf,
0x00,0x99,0x29,0xb0,0x52,0xcb,0x7b,0xe2,
0xa4,0x3d,0x8d,0x14,0xf6,0x6f,0xdf,0x46};

//
byte get_taffineValue(byte loc){  
	return taffine[loc]; 
}

void set_taffineValue(byte loc, byte value){
	taffine[loc] = value;
}


void gensquare()
{
  int i;
  byte x=0;
  printf("byte sq[256]={");
  for(i=0;i<256;i++)
  {
    if((i%8)==0) printf("\n");
    printf("0x%02x",mult(x,x));
    x++;
    if(i<255) printf(",");
  }
  printf("};\n");
}

byte square(byte x)
{
  //return mult(x,x);
  return sq[x];
}

void gentaffine()
{
  int i;
  byte x=0;
  printf("byte taffine[256]={");
  for(i=0;i<256;i++)
  {
    if((i%8)==0) printf("\n");
    printf("0x%02x",affine(x));
    x++;
    if(i<255) printf(",");
  }
  printf("};\n");
}

void gensmall_multtable()
{
  int i,j;
  byte x,y;
  byte t[1024];
  for(i=0;i<2;i++)
    for(j=0;j<2;j++)
      for(x=0;x<16;x++)
	for(y=0;y<16;y++)
	  t[(i << 9) | (j << 8) | (x << 4) | y]=mult(x << (i*4),y << (j*4));
   printf("byte tsmult[1024]={");
   for(i=0;i<1024;i++)
   {
      if((i%8)==0) printf("\n");
      printf("0x%02x",t[i]);
      if(i<1023) printf(",");
   }
   printf("};\n");
}

// Computes z=x*y in GF(2^8) using four 8-bit tables 
byte multtable(byte x,byte y)
{
  return tsmult[0   | ((x & 15) << 4) | (y & 15)] ^
         tsmult[512 | (x & 240) | (y & 15)] ^
         tsmult[256 | ((x & 15) << 4) | (y >> 4)] ^
         tsmult[768 | (x & 240) | (y >> 4)];
}

// AES Sbox computation without masking
byte subbyte_rp(byte x)
{
  byte u2=square(x);
  byte u3=multtable(u2,x);
  byte u6=square(u3);
  byte u7=multtable(u6,x);
  byte u14=square(u7);
  byte u15=multtable(u14,x);
  byte u240=square(square(square(square(u15))));
  byte u254=multtable(u240,u14);
  return taffine[u254];
}

void square_share(byte *a,int n)
{
  int i;
  for(i=0;i<n;i++)
    a[i]=square(a[i]);
}

// The shared multiplication SecMult of Rivain-Prouff
void multshare(byte *a,byte *b,byte *c,int n)
{
  // Memory: 4 bytes
  int i,j; 
  for(i=0;i<n;i++)
    c[i]=multtable(a[i],b[i]);

  for(i=0;i<n;i++)
  {
    for(j=i+1;j<n;j++)
    {
      byte tmp=xorshf96(); //rand();
      byte tmp2=(tmp ^ multtable(a[i],b[j])) ^ multtable(a[j],b[i]);
      c[i]^=tmp;
      c[j]^=tmp2;
    }
  }
}

void subbyte_rp_share_func(byte *a,int n,void (*multshare_call)(byte *,byte *,byte *,int)){
  // Memory: 5*n+5 byte 
  int i;
  byte z[n],z2[n];
  byte one[n];

  for(i=1;i<n;i++)
    one[i]=0;

  one[0]=1;

  memcpy(z,a,n);
  square_share(z,n);    // z=x^2     

  multshare_call(z,one,z2,n);  // z=Refresh(z)
  memcpy(z,z2,n);

  byte y[n];
  multshare_call(z,a,y,n);   // y=z*x=x^3

  byte w[n];
  memcpy(w,y,n);
  square_share(w,n);
  square_share(w,n);     // w=x^12

  byte w2[n];
  multshare_call(w,one,w2,n); // w=Refresh(w)
  memcpy(w,w2,n);

  byte y2[n];
  multshare_call(y,w,y2,n);   // y2=x^15

  square_share(y2,n);
  square_share(y2,n);
  square_share(y2,n);
  square_share(y2,n);    // y2=x^240
  
  multshare_call(w,y2,y,n);   // y=x^252
  multshare_call(y,z,a,n);    // a=x^254
  for(i=0;i<n;i++)
    a[i]=taffine[a[i]];
  if((n%2)==0)
    a[0]^=99;
}

void subbyte_rp_share_func_no_error(byte *a,int n,void (*multshare_call)(byte *,byte *,byte *,int)){
  // Memory: 5*n+5 byte 
  int i;
  byte z[n],z2[n];
  byte one[n];

  for(i=1;i<n;i++)
    one[i]=0;

  one[0]=1;

  memcpy(z,a,n);
  square_share(z,n);    // z=x^2     

  multshare_call(z,one,z2,n);  // z=Refresh(z)
  memcpy(z,z2,n);

  byte y[n];
  multshare_call(z,a,y,n);   // y=z*x=x^3

  byte w[n];
  memcpy(w,y,n);
  square_share(w,n);
  square_share(w,n);     // w=x^12

  byte w2[n];
  multshare_call(w,one,w2,n); // w=Refresh(w)
  memcpy(w,w2,n);

  byte y2[n];
  multshare_call(y,w,y2,n);   // y2=x^15

  square_share(y2,n);
  square_share(y2,n);
  square_share(y2,n);
  square_share(y2,n);    // y2=x^240
  
  multshare_call(w,y2,y,n);   // y=x^252
  multshare_call(y,z,a,n);    // a=x^254
  for(i=0;i<n;i++)
    a[i]=taffine_no_error[a[i]];
  if((n%2)==0)
    a[0]^=99;
}

void subbyte_rp_share_func_no_error_print(byte *a,int n,void (*multshare_call)(byte *,byte *,byte *,int)){
  // Memory: 5*n+5 byte 
  
  int i;
  byte z[n],z2[n];
  byte one[n];

  for(i=1;i<n;i++)
    one[i]=0;

  one[0]=1;

  memcpy(z,a,n);
  square_share(z,n);    // z=x^2     

  multshare_call(z,one,z2,n);  // z=Refresh(z)
  memcpy(z,z2,n);

  byte y[n];
  multshare_call(z,a,y,n);   // y=z*x=x^3

  byte w[n];
  memcpy(w,y,n);
  square_share(w,n);
  square_share(w,n);     // w=x^12

  byte w2[n];
  multshare_call(w,one,w2,n); // w=Refresh(w)
  memcpy(w,w2,n);

  byte y2[n];
  multshare_call(y,w,y2,n);   // y2=x^15

  square_share(y2,n);
  square_share(y2,n);
  square_share(y2,n);
  square_share(y2,n);    // y2=x^240
  
  multshare_call(w,y2,y,n);   // y=x^252
  multshare_call(y,z,a,n);    // a=x^254
  FILE *fpWrite = fopen("encrypt_state.txt", "a+");
  if(n==2){
    fprintf(fpWrite,"%02x^%02x = %02x\t",a[0],a[1],a[0]^a[1]);
  }
  else if(n==3){
    fprintf(fpWrite,"%02x^%02x^%02x = %02x\t",a[0],a[1],a[2],a[0]^a[1]^a[2]);
  }
  else if(n==4){
    fprintf(fpWrite,"%02x^%02x^%02x^%02x = %02x\t",a[0],a[1],a[2],a[3],a[0]^a[1]^a[2]^a[3]);
  }
  for(i=0;i<n;i++)
    a[i]=taffine_no_error[a[i]];
  if((n%2)==0)
    a[0]^=99;
  fclose(fpWrite);
}

void subbyte_rp_share_func_print(byte *a,int n,void (*multshare_call)(byte *,byte *,byte *,int)){
  //printf("进入：%02x^%02x^%02x = %02x\n",a[0],a[1],a[2],a[0]^a[1]^a[2]);
  // Memory: 5*n+5 byte 
  int i;
  byte z[n],z2[n];
  byte one[n];

  for(i=1;i<n;i++)
    one[i]=0;

  one[0]=1;

  memcpy(z,a,n);
  square_share(z,n);    // z=x^2     

  multshare_call(z,one,z2,n);  // z=Refresh(z)
  memcpy(z,z2,n);

  byte y[n];
  multshare_call(z,a,y,n);   // y=z*x=x^3

  byte w[n];
  memcpy(w,y,n);
  square_share(w,n);
  square_share(w,n);     // w=x^12

  byte w2[n];
  multshare_call(w,one,w2,n); // w=Refresh(w)
  memcpy(w,w2,n);

  byte y2[n];
  multshare_call(y,w,y2,n);   // y2=x^15

  square_share(y2,n);
  square_share(y2,n);
  square_share(y2,n);
  square_share(y2,n);    // y2=x^240
  
  multshare_call(w,y2,y,n);   // y=x^252
  multshare_call(y,z,a,n);    // a=x^254
  FILE *fpWrite = fopen("encrypt_state.txt", "a+");
  if(n==2){
    fprintf(fpWrite,"%02x^%02x = %02x\t",a[0],a[1],a[0]^a[1]);
  }
  else if(n==3){
    fprintf(fpWrite,"%02x^%02x^%02x = %02x\t",a[0],a[1],a[2],a[0]^a[1]^a[2]);
  }
  else if(n==4){
    fprintf(fpWrite,"%02x^%02x^%02x^%02x = %02x\t",a[0],a[1],a[2],a[3],a[0]^a[1]^a[2]^a[3]);
  }
  for(i=0;i<n;i++)
    a[i]=taffine[a[i]];
  if((n%2)==0)
    a[0]^=99;
  //printf("出去：%02x^%02x^%02x = %02x\n",a[0],a[1],a[2],a[0]^a[1]^a[2]);
  fclose(fpWrite);
}

void subbyte_rp_share(byte *a,int n)
{
  subbyte_rp_share_func(a,n,multshare);
}

void subbyte_rp_share_no_error(byte *a,int n)
{
  subbyte_rp_share_func_no_error(a,n,multshare);
}

void subbyte_rp_share_no_error_print(byte *a,int n)
{
  subbyte_rp_share_func_no_error_print(a,n,multshare);
}

void subbyte_rp_share_print(byte *a,int n)
{
  subbyte_rp_share_func_print(a,n,multshare);
}

// AES with RP Sbox computation without masking
void subbytestate_rp(byte *state)
{
  int i;
  for(i=0;i<16;i++) state[i]=subbyte_rp(state[i]);
}

// AES with RP Sbox computation without masking
void aes_rp(byte in[16],byte out[16],byte key[16])
{
  int i,j;
  int round=0;
  byte state[16];
  byte w[176];

  keyexpansion(key,w);

  for(i=0;i<16;i++)
    state[i]=in[i];

  addroundkey(state,w,0);

  for(round=1;round<10;round++)
  { 
    subbytestate_rp(state);
    shiftrows(state);
    mixcolumns(state);
    addroundkey(state,w,round);
  }
 
  subbytestate(state);
  shiftrows(state);
  addroundkey(state,w,10);

  for(i=0;i<16;i++)
    out[i]=state[i];
}



