/* bn_sample.c */
#include <stdio.h>
#include <openssl/bn.h>
#define NBITS 256


void printBN(char *msg, BIGNUM * a)
{
	/* Use BN_bn2hex(a) for hex string
	/* Use BN_bn2dec(a) for decimal string */
	char * number_str = BN_bn2hex(a);
	printf("%s %s\n", msg, number_str);
	OPENSSL_free(number_str);
}


int main ()
{
	BN_CTX *ctx = BN_CTX_new();
	
	BIGNUM *d = BN_new();
	BIGNUM *n = BN_new();
	BIGNUM *m = BN_new();
	BIGNUM *sign_1 = BN_new();
	BIGNUM *m1 = BN_new();
	BIGNUM *sign_2 = BN_new();
	BIGNUM *e = BN_new();
	
	BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
	BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
	BN_hex2bn(&e, "010001");
	// I owe you $2000. ---> 49206f776520796f752024323030302e
	BN_hex2bn(&m, "49206f776520796f752024323030302e");
	
	
	// sign = mˆd mod n (Encryption)
	BN_mod_exp(sign_1,m, d, n, ctx);
	printBN("First Signature = ", sign_1);
	
	
	// I owe you $3000. ----> 49206f776520796f752024323030302e
	BN_hex2bn(&m1, "49206f776520796f752024323030302e");
	BN_mod_exp(sign_2,m1, d, n, ctx);
	printBN("Second Signature = ", sign_2);
	
	
	// Comparism of both signatures.
	int sign_cmp = BN_cmp(sign_1, sign_2);
	
	if(sign_cmp == 1){
		printf("Both Signatures are Equal\n");
	}
	else{
		printf("Signatures are not Equal\n");
	}
	
	return 0;
}
