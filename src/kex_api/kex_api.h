
#define KEX_SECRETKEYBYTES 8608
#define KEX_PUBLICKEYBYTES 9968
#define KEX_BYTES 32
#define KEX_ALGNAME "lwe_okcn"


int kex_keygen(unsigned char *pk, unsigned char *sk);
int kex_kdf(unsigned char *pk, unsigned char *sk, unsigned char *ss);
