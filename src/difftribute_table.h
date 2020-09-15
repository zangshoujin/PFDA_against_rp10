#ifndef __difftribute_h__
#define __difftribute_h__

extern struct In_Out_Diff{
	byte in_diff;
	byte in1;
	byte in2;
	byte out_diff;
	byte out1;
	byte out2;
}in_out_diff[65536];

extern struct Table{
	unsigned int value;
	byte in1[2];
	byte in2[2];
	byte in_diff[2];
	byte out1[2];
	byte out2[2];
	byte out_diff[2];
}table[256][256];

void diff_table();

#endif