
#define KEX_SECRETKEYBYTES 8608
#define KEX_PUBLICKEYBYTES 9968
#define KEX_BYTES 32
#define KEX_ALGNAME "lwe_okcn"

/* setup system params */
bool setup();

/* generate exchange information */
int kex_keygen(unsigned char **pk, unsigned char **sk);

/* export shared secret key */
int kex_kdf(unsigned char *pk, unsigned char *sk, unsigned char **ss);

/* clean allocated resource */
void clean_up();

