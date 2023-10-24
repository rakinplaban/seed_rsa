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
	BIGNUM *p = BN_new();
	BIGNUM *p_1 = BN_new();
	BIGNUM *q = BN_new();
	BIGNUM *q_1 = BN_new();
	BIGNUM *e = BN_new();
	BIGNUM *d = BN_new();
	BIGNUM *n = BN_new();
	BIGNUM *n_fi = BN_new();
	BIGNUM *one = BN_new();
	BIGNUM *i_one = BN_new();
	BIGNUM *res = BN_new();
	// Initialize a, b, n
	//BN_generate_prime_ex(a, NBITS, 1, NULL, NULL, NULL);
	
	BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DF");
	BN_hex2bn(&q, "E85CED54AF57E53E092113E62F436F4F");
	BN_hex2bn(&e, "0D88C3");
	
	BN_dec2bn(&one,"1");
	BN_dec2bn(&i_one,"-1");
	
	
	BN_sub(p_1, p, one);
	printBN("p - 1 = ", p_1);
	
	BN_sub(q_1, q, one);
	printBN("q - 1 = ", q_1);
	
	//BN_rand(n, NBITS, 0, 0);
	// n = p*q
	
	BN_mul(n_fi, p_1, q_1, ctx);
	printBN("n_fi = ", n_fi);
	
	BN_mod_exp(d, e, i_one, n_fi, ctx);
	printBN("d = ", d);
	// res = aˆb mod n
	// BN_mod_exp(res, d, e, n_fi, ctx);
	// printBN("de mod n_fi = ", res);
	return 0;
}
