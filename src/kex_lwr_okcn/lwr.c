#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "local.h"

#include <oqs/aes.h>

#define min(x, y) (((x) < (y)) ? (x) : (y))

// Pack the input uint16 vector into a char output vector, copying lsb bits
// from each input element. If inlen * lsb / 8 > outlen, only outlen * 8 bits
// are copied.
void oqs_kex_lwr_okcn_pack(unsigned char *out, const size_t outlen, const uint16_t *in, const size_t inlen, const unsigned char lsb) {
	memset(out, 0, outlen);

	size_t i = 0;            // whole bytes already filled in
	size_t j = 0;            // whole uint16_t already copied
	uint16_t w = 0;          // the leftover, not yet copied
	unsigned char bits = 0;  // the number of lsb in w
	while (i < outlen && (j < inlen || ((j == inlen) && (bits > 0)))) {
		/*
		in: |        |        |********|********|
		                      ^
		                      j
		w : |   ****|
		        ^
		       bits
		out:|**|**|**|**|**|**|**|**|* |
		                            ^^
		                            ib
		*/
		unsigned char b = 0;  // bits in out[i] already filled in
		while (b < 8) {
			int nbits = min(8 - b, bits);
			uint16_t mask = (1 << nbits) - 1;
			unsigned char t = (w >> (bits - nbits)) & mask;  // the bits to copy from w to out
			out[i] = out[i] + (t << (8 - b - nbits));
			b += nbits;
			bits -= nbits;
			w &= ~(mask << bits);  // not strictly necessary; mostly for debugging

			if (bits == 0) {
				if (j < inlen) {
					w = in[j];
					bits = lsb;
					j++;
				} else {
					break;  // the input vector is exhausted
				}
			}
		}
		if (b == 8) {  // out[i] is filled in
			i++;
		}
	}
}

// Unpack the input char vector into a uint16_t output vector, copying lsb bits
// for each output element from input. outlen must be at least ceil(inlen * 8 /
// lsb).
void oqs_kex_lwr_okcn_unpack(uint16_t *out, const size_t outlen, const unsigned char *in, const size_t inlen, const unsigned char lsb) {
	memset(out, 0, outlen * sizeof(uint16_t));

	size_t i = 0;            // whole uint16_t already filled in
	size_t j = 0;            // whole bytes already copied
	unsigned char w = 0;     // the leftover, not yet copied
	unsigned char bits = 0;  // the number of lsb bits of w
	while (i < outlen && (j < inlen || ((j == inlen) && (bits > 0)))) {
		/*
		in: |  |  |  |  |  |  |**|**|...
		                      ^
		                      j
		w : | *|
		      ^
		      bits
		out:|   *****|   *****|   ***  |        |...
		                      ^   ^
		                      i   b
		*/
		unsigned char b = 0;  // bits in out[i] already filled in
		while (b < lsb) {
			int nbits = min(lsb - b, bits);
			uint16_t mask = (1 << nbits) - 1;
			unsigned char t = (w >> (bits - nbits)) & mask;  // the bits to copy from w to out
			out[i] = out[i] + (t << (lsb - b - nbits));
			b += nbits;
			bits -= nbits;
			w &= ~(mask << bits);  // not strictly necessary; mostly for debugging

			if (bits == 0) {
				if (j < inlen) {
					w = in[j];
					bits = 8;
					j++;
				} else {
					break;  // the input vector is exhausted
				}
			}
		}
		if (b == lsb) {  // out[i] is filled in
			i++;
		}
	}
}

#define LWR_DIV_ROUNDUP(x, y) (((x) + (y)-1) / y)

// define parameters for "recommended" parameter set
#define PARAMS_N 680
#define PARAMS_NBAR 8
#define PARAMS_LOG2Q 15
#define PARAMS_LOG2P 12
#define PARAMS_TAIL_LEN 3
#define PARAMS_TAIL_MASK 0x7
#define PARAMS_Q (1 << PARAMS_LOG2Q)
#define PARAMS_P (1 << PARAMS_LOG2P)
#define PARAMS_EXTRACTED_BITS 4
#define PARAMS_KEY_BITS 256
#define PARAMS_STRIPE_STEP 8
#define PARAMS_SINGLE_HINT_BITS 8
#define PARAMS_REC_HINT_LENGTH LWR_DIV_ROUNDUP(PARAMS_NBAR * PARAMS_NBAR * PARAMS_SINGLE_HINT_BITS, 8)
// pre-process code to obtain "recommended" functions
#define MACRIFY(NAME) NAME ## _recommended

void MACRIFY(oqs_kex_lwr_okcn_con)(unsigned char *bob_rec, unsigned char *key, uint16_t *in) {
	int i;
	for (i = 0; i < PARAMS_NBAR * PARAMS_NBAR; i++) {
		bob_rec[i] = in[i] & 0xFF;
		in[i] >>= 8;  // drop least bits
	}
	oqs_kex_lwr_okcn_pack(key, PARAMS_KEY_BITS / 8, in, PARAMS_NBAR * PARAMS_NBAR, PARAMS_EXTRACTED_BITS);
}

void MACRIFY(oqs_kex_lwr_okcn_rec)(unsigned char *key, uint16_t *w, const unsigned char *hint) {
	int i;
	for (i = 0; i < PARAMS_NBAR * PARAMS_NBAR; i++) {
		w[i] = (w[i] - ((uint16_t)hint[i]) + 128) >> 8;
	}
	oqs_kex_lwr_okcn_pack(key, PARAMS_KEY_BITS / 8, w, PARAMS_NBAR * PARAMS_NBAR, PARAMS_EXTRACTED_BITS);
}

// Generate-and-multiply: generate A row-wise, multiply by s on the right then rounding_p.
int MACRIFY(oqs_kex_lwr_okcn_mul_round_as_on_the_fly)(uint16_t *out, const uint16_t *s, struct oqs_kex_lwr_okcn_params *params) {
	// A (N x N)
	// s (N x N_BAR)
	// out = round(A * s)_p (N x N_BAR)

	int i, j, k;
	int ret = 0;
	uint16_t *a_row = NULL;
	uint16_t *s_transpose = NULL;

	size_t a_rowlen = PARAMS_N * sizeof(int16_t);
	a_row = (uint16_t *)malloc(a_rowlen);
	if (a_row == NULL) {
		goto err;
	}

	// transpose s to store it in the column-major order
	s_transpose = (uint16_t *)malloc(PARAMS_NBAR * PARAMS_N * sizeof(int16_t));
	if (s_transpose == NULL) {
		goto err;
	}

	for (j = 0; j < PARAMS_N; j++) {
		for (k = 0; k < PARAMS_NBAR; k++) {
			s_transpose[k * PARAMS_N + j] = s[j * PARAMS_NBAR + k];
		}
	}

	assert(params->seed_len == 16);
	void *aes_key_schedule = NULL;
	OQS_AES128_load_schedule(params->seed, &aes_key_schedule, 1);

	for (i = 0; i < PARAMS_N; i++) {
		// go through A's rows
		memset(a_row, 0, a_rowlen);
		for (j = 0; j < PARAMS_N; j += PARAMS_STRIPE_STEP) {
			// Loading values in the little-endian order!
			a_row[j] = i;
			a_row[j + 1] = j;
		}

		OQS_AES128_ECB_enc_sch((uint8_t *)a_row, a_rowlen, aes_key_schedule, (uint8_t *)a_row);

		for (k = 0; k < PARAMS_NBAR; k++) {
			uint16_t sum = 0;
			for (j = 0; j < PARAMS_N; j++) {
				// matrix-vector multiplication happens here
				sum += a_row[j] * s_transpose[k * PARAMS_N + j];
			}
			// We use floor here!
			out[i * PARAMS_NBAR + k] = sum >> PARAMS_TAIL_LEN;
		}
	}

	OQS_AES128_free_schedule(aes_key_schedule);

	ret = 1;
	goto cleanup;

err:
	memset(out, 0, PARAMS_NBAR * PARAMS_N * sizeof(uint16_t));

cleanup:
	if (a_row != NULL) {
		memset(a_row, 0, a_rowlen);
		free(a_row);
	}

	if (s_transpose != NULL) {
		memset(s_transpose, 0, PARAMS_NBAR * PARAMS_N * sizeof(int16_t));
		free(s_transpose);
	}

	return ret;
}

// Generate-and-multiply: generate A column-wise, multiply by s' on the left.
int MACRIFY(oqs_kex_lwr_okcn_mul_round_sa_on_the_fly)(uint16_t *out, const uint16_t *s, struct oqs_kex_lwr_okcn_params *params)
{
	// a (N x N)
	// s' (N_BAR x N)
	// out = round(s'a)_p (N_BAR x N)

	int i, j, k, kk;
	int ret = 0;
	uint16_t *a_cols = NULL;
	uint16_t *a_cols_t = NULL;

	size_t a_colslen = PARAMS_N * PARAMS_STRIPE_STEP * sizeof(int16_t);
	// a_cols stores 8 columns of A at a time.
	a_cols = (uint16_t *)malloc(a_colslen);
	a_cols_t = (uint16_t *)malloc(a_colslen);  // a_cols transposed (stored in the column-major order).
	if ((a_cols == NULL) || (a_cols_t == NULL)) {
		goto err;
	}

	assert(params->seed_len == 16);
	void *aes_key_schedule = NULL;
	OQS_AES128_load_schedule(params->seed, &aes_key_schedule, 1);

	for (kk = 0; kk < PARAMS_N; kk += PARAMS_STRIPE_STEP) {
		// Go through A's columns, 8 (== PARAMS_STRIPE_STEP) columns at a time.
		memset(a_cols, 0, a_colslen);
		for (i = 0; i < PARAMS_N; i++) {
			// Loading values in the little-endian order!
			a_cols[i * PARAMS_STRIPE_STEP] = i;
			a_cols[i * PARAMS_STRIPE_STEP + 1] = kk;
		}

		OQS_AES128_ECB_enc_sch((uint8_t *)a_cols, a_colslen, aes_key_schedule, (uint8_t *)a_cols);

		// transpose a_cols to have access to it in the column-major order.
		for (i = 0; i < PARAMS_N; i++)
			for (k = 0; k < PARAMS_STRIPE_STEP; k++) {
				a_cols_t[k * PARAMS_N + i] = a_cols[i * PARAMS_STRIPE_STEP + k];
			}

		for (i = 0; i < PARAMS_NBAR; i++)
			for (k = 0; k < PARAMS_STRIPE_STEP; k++) {
				uint16_t sum = 0;
				for (j = 0; j < PARAMS_N; j++) {
					sum += s[i * PARAMS_N + j] * a_cols_t[k * PARAMS_N + j];
				}
				// we use rounding here!
				out[i * PARAMS_N + kk + k] = (sum + 4) >> PARAMS_TAIL_LEN;
			}
	}

	OQS_AES128_free_schedule(aes_key_schedule);

	ret = 1;
	goto cleanup;

err:
	memset(out, 0, PARAMS_NBAR * PARAMS_N * sizeof(uint16_t));

cleanup:
	if (a_cols != NULL) {
		memset(a_cols, 0, a_colslen);
		free(a_cols);
	}

	if (a_cols_t != NULL) {
		memset(a_cols_t, 0, a_colslen);
		free(a_cols_t);
	}

	return ret;
}

// multiply by s on the right
void MACRIFY(oqs_kex_lwr_okcn_mul_bs)(uint16_t *out, const uint16_t *b, const uint16_t *s) {
	// b (N_BAR x N)
	// s (N x N_BAR)
	// out = bs
	int i, j, k;
	for (i = 0; i < PARAMS_NBAR; i++) {
		for (j = 0; j < PARAMS_NBAR; j++) {
			out[i * PARAMS_NBAR + j] = 0;
			for (k = 0; k < PARAMS_N; k++) {
				out[i * PARAMS_NBAR + j] += b[i * PARAMS_N + k] * s[k * PARAMS_NBAR + j];
			}
		}
	}
}

// multiply by s on the left
int MACRIFY(oqs_kex_lwr_okcn_mul_round_sb)(uint16_t *out, const uint16_t *b, const uint16_t *s, OQS_RAND *rand) {
	// b (N x N_BAR)
	// s (N_BAR x N)
	// out = round(s(b + eps))_p

	int i, j, k;
	size_t rndlen = PARAMS_N * PARAMS_NBAR * 2;
	uint16_t *rndvec = (uint16_t *)malloc(rndlen);
	if (rndvec == NULL) {
		return 0;
	}
	OQS_RAND_n(rand, (uint8_t *)rndvec, rndlen);

	for (k = 0; k < PARAMS_NBAR; k++) {
		for (i = 0; i < PARAMS_NBAR; i++) {
			uint16_t sum = 0;
			for (j = 0; j < PARAMS_N; j++) {
				// since we take floor when generating b, add random value back directly
				sum += s[k * PARAMS_N + j] * ((b[j * PARAMS_NBAR + i] << PARAMS_TAIL_LEN) |
					(rndvec[j * PARAMS_NBAR + i] & PARAMS_TAIL_MASK));
			}
			out[k * PARAMS_NBAR + i] = sum >> PARAMS_TAIL_LEN;
		}
	}
	free(rndvec);
	return 1;
}



// undefine macros to avoid any confusion later
#undef PARAMS_SINGLE_HINT_BITS
#undef PARAMS_N
#undef PARAMS_NBAR
#undef PARAMS_LOG2Q
#undef PARAMS_LOG2P
#undef PARAMS_Q
#undef PARAMS_P
#undef PARAMS_TAIL_LEN
#undef PARAMS_TAIL_MASK
#undef PARAMS_EXTRACTED_BITS
#undef PARAMS_KEY_BITS
#undef PARAMS_STRIPE_STEP
#undef PARAMS_REC_HINT_LENGTH
#undef MACRIFY
