#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <oqs/kex.h>
#include <oqs/rand.h>

#include "kex_api.h"

#define PRINT_HEX_STRING(label, str, len)                        \
	{                                                            \
		printf("%-20s (%4zu bytes):  ", (label), (size_t)(len)); \
		for (size_t i = 0; i < (len); i++) {                     \
			printf("%02X", ((unsigned char *) (str))[i]);        \
		}                                                        \
		printf("\n");                                            \
	}

OQS_KEX *kex = NULL;
int rc;

void *alice_priv = NULL;
uint8_t *alice_msg = NULL;
size_t alice_msg_len;
uint8_t *alice_key = NULL;
size_t alice_key_len;

uint8_t *bob_msg = NULL;
size_t bob_msg_len;
uint8_t *bob_key = NULL;
size_t bob_key_len;

bool setup() {
	/* setup RAND */
	OQS_RAND *rand = OQS_RAND_new(OQS_RAND_alg_urandom_chacha20);
	if (rand == NULL) {
		return false;
	}

	kex = OQS_KEX_new(rand, OQS_KEX_alg_lwe_okcn, "01234567890123456", 16, "recommended");
	if (kex == NULL) {
		fprintf(stderr, "new_method failed\n");
		return false;
	}

	return true;
}

int kex_keygen(unsigned char **pk, unsigned char **sk) {
	/* Alice's initial message */
	rc = OQS_KEX_alice_0(kex, &alice_priv, &alice_msg, &alice_msg_len);
	if (rc != 1) {
		fprintf(stderr, "OQS_KEX_alice_0 failed\n");
	}

//	PRINT_HEX_STRING("Alice message", alice_msg, alice_msg_len)

	/* Bob's response */
	rc = OQS_KEX_bob(kex, alice_msg, alice_msg_len, &bob_msg, &bob_msg_len, &bob_key, &bob_key_len);
	if (rc != 1) {
		fprintf(stderr, "OQS_KEX_bob failed\n");
	}

//	PRINT_HEX_STRING("Bob message", bob_msg, bob_msg_len)

//	PRINT_HEX_STRING("Bob session key", bob_key, bob_key_len)

	*pk = alice_msg;

	printf("gen pk: %p\n", pk);

	*sk = bob_msg;

	return 1;
}

int kex_kdf(unsigned char *pk, unsigned char *sk, unsigned char **ss) {

	/* Alice processes Bob's response */
	rc = OQS_KEX_alice_1(kex, alice_priv, bob_msg, bob_msg_len, &alice_key, &alice_key_len);
	if (rc != 1) {
		fprintf(stderr, "OQS_KEX_alice_1 failed\n");
	}

	*ss = alice_key;

	// PRINT_HEX_STRING("Alice session key", alice_key, alice_key_len)

	return 1;
}

void clean_up() {
	free(alice_key);
	free(bob_key);
	OQS_KEX_alice_priv_free(kex, alice_priv);
	OQS_KEX_free(kex);
}

int main() {

	unsigned char *pk = NULL;
	unsigned char *sk = NULL;
	unsigned char *ss = NULL;
	
	setup();

	kex_keygen(&pk, &sk);

	printf("pk:%p\n", pk);
	printf("alice msg:%p\n", alice_msg);

	PRINT_HEX_STRING("Alice's exchange information", pk, KEX_PUBLICKEYBYTES)

	PRINT_HEX_STRING("Bob's exchange information", sk, KEX_SECRETKEYBYTES)

	kex_kdf(pk, sk, &ss);

	PRINT_HEX_STRING("Shaerd secret", ss, KEX_BYTES)

	clean_up();

	return 1;
}
