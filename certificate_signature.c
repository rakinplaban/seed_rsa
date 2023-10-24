#include <stdio.h>
#include <openssl/bn.h>

void printBN(char *msg, BIGNUM *a) {
    char *number_str = BN_bn2hex(a);
    printf("%s %s\n", msg, number_str);
    OPENSSL_free(number_str);
}

int main() {
    BN_CTX *ctx = BN_CTX_new();

    BIGNUM *n = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *cb = BN_new();
    BIGNUM *s = BN_new();
    BIGNUM *dec_s = BN_new();

    BN_hex2bn(&n, "A07D124943C39594B531CED6EB52EB50FFB8278837BCE9F279FC8F1D21788D6017BE34B58E8E19184EE3BCF7371FBC3F4651FA6D0C3DB608AC057ABF9873307410375C43D0C997284F64EA7F9619ECD976FE8B3D004D9767DFA5DCA152C3DB6864935B2ABCBABC96AEA1B26DAAED730BAECB4FE2EB3FACFAEAE74CE71DF1664F096166FC6AC23C8157549B9A3B92479AAE837C3C40672101C8C70EA1B1DF95657C1657CD8EF97BD31695CBB0513FC18AEC03BFCF728747543CDA3576DFDE9A7246866E6AD5F5BC01F41960C8667229A8B7FBC9EAE12F9F882D60000A743BEC7715E9E4BC0E9F697DBA90C531B2961D729D0FC8A8ECCA430B4087EB436C061C77");
    BN_hex2bn(&e, "65537");
    BN_hex2bn(&cb, "bbd1f60156c78888d1e82d88f4244881a25b56fffddfb87fe08d0c2e03a305af");
    BN_hex2bn(&s, "631435a8783f0eb40d85906ed947d2315876f34cb3e56c876ece40461b844da2b465acd09bef4140ecb7b63e8cc1cfadee4d66d766af54679901685687d3bf0c50c6d27854ea897e1d97d4b4efe15ad923d9ba9412cdef6f420cefd329e54ff6189f955a9eedf6805d3f0a0441703d613921ffb356a4b1def3e60f1f9133b39762b5738449a15558d1abbc8035417ea315bae332b8cec373606500ca9d609889da5ca3795d2464963d7466b54771dd172ee00c13ff7ee78066ed3bd17c8e3a85f09fbba15b40f217de083ee63f8c64949d22e4097735e1315010625a6edbbdfcd7f4ecd92b83c7abff719f2557c0f9a3fc53b42a560272f13366f14b256761b9");

    // Verify the signature
    BN_mod_exp(dec_s, s, e, n, ctx);
    
    printBN("Certificate Body = ",cb);
    
    printf("\n\n");
    
    printBN("Decrypted Signature = ",dec_s);
    
    printf("\n\n");

    if (BN_cmp(cb, dec_s) == 0) {
        printf("Signature is valid. Certificate body matches the decrypted signature.\n");
    } else {
        printf("Signature is not valid. Certificate body does not match the decrypted signature.\n");
    }

    return 0;
}

