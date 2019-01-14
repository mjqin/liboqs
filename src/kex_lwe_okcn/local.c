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
void oqs_kex_lwe_okcn_pack(unsigned char *out, const size_t outlen, const uint16_t *in, const size_t inlen, const unsigned char lsb) {
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
void oqs_kex_lwe_okcn_unpack(uint16_t *out, const size_t outlen, const unsigned char *in, const size_t inlen, const unsigned char lsb) {
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

static int lwe_sample_n_inverse_8(uint16_t *s, const size_t n, const uint8_t *cdf_table, const size_t cdf_table_len, OQS_RAND *rand) {

	/* Fills vector s with n samples from the noise distribution which requires
	* 8 bits to sample. The distribution is specified by its CDF. Super-constant
	* timing: the CDF table is ingested for every sample.
	*/

	size_t rndlen = n;
	uint8_t *rndvec = (uint8_t *)malloc(rndlen);
	if (rndvec == NULL) {
		fprintf(stderr, "malloc failure\n");
		return 0;
	}
	OQS_RAND_n(rand, rndvec, rndlen);

	size_t i, j;

	for (i = 0; i < n; ++i) {
		uint8_t sample = 0;
		uint8_t rnd = rndvec[i] >> 1; // drop the least significant bit
		uint8_t sign = rndvec[i] & 0x1; // pick the least significant bit

										// No need to compare with the last value.
		for (j = 0; j < cdf_table_len - 1; j++) {
			// Constant time comparison: 1 if cdf_table[j] < rnd, 0 otherwise.
			// Critically uses the fact that cdf_table[j] and rnd fit in 7 bits.
			sample += (uint8_t)(cdf_table[j] - rnd) >> 7;
		}
		// Assuming that sign is either 0 or 1, flips sample iff sign = 1
		s[i] = ((-sign) ^ sample) + sign;
	}

	memset(rndvec, 0, rndlen);
	free(rndvec);
	return 1;
}

static int lwe_sample_n_inverse_12(uint16_t *s, const size_t n, const uint16_t *cdf_table, const size_t cdf_table_len, OQS_RAND *rand) {
	/* Fills vector s with n samples from the noise distribution which requires
	* 12 bits to sample. The distribution is specified by its CDF. Super-constant
	* timing: the CDF table is ingested for every sample.
	*/

	size_t rndlen = 3 * ((n + 1) / 2);  // 12 bits of unif randomness per output element

	uint8_t *rnd = (uint8_t *)malloc(rndlen);
	if (rnd == NULL) {
		fprintf(stderr, "malloc failure\n");
		return 0;
	}
	OQS_RAND_n(rand, rnd, rndlen);

	size_t i;

	for (i = 0; i < n; i += 2) {  // two output elements at a time
		uint8_t *pRnd = (rnd + 3 * i / 2);

		uint16_t rnd1 = (((pRnd[0] << 8) + pRnd[1]) & 0xFFE0) >> 5; // first 11 bits (0..10)
		uint16_t rnd2 = (((pRnd[1] << 8) + pRnd[2]) & 0x1FFC) >> 2; // next 11 bits (11..21)

		uint8_t sample1 = 0;
		uint8_t sample2 = 0;

		size_t j;
		// No need to compare with the last value.
		for (j = 0; j < cdf_table_len - 1; j++) {
			// Constant time comparison: 1 if LWE_CDF_TABLE[j] < rnd1, 0 otherwise.
			// Critically uses the fact that LWE_CDF_TABLE[j] and rnd1 fit in 15 bits.
			sample1 += (uint16_t)(cdf_table[j] - rnd1) >> 15;
			sample2 += (uint16_t)(cdf_table[j] - rnd2) >> 15;
		}

		uint8_t sign1 = (pRnd[2] & 0x02) >> 1; // 22nd bit
		uint8_t sign2 = pRnd[2] & 0x01; // 23rd bit

										// Assuming that sign1 is either 0 or 1, flips sample1 iff sign1 = 1
		s[i] = ((-sign1) ^ sample1) + sign1;

		if (i + 1 < n) {
			s[i + 1] = ((-sign2) ^ sample2) + sign2;
		}
	}

	memset(rnd, 0, rndlen);
	free(rnd);
	return 1;
}

static int lwe_sample_n_inverse_16(uint16_t *s, const size_t n, const uint16_t *cdf_table, const size_t cdf_table_len, OQS_RAND *rand) {
	/* Fills vector s with n samples from the noise distribution which requires
	* 16 bits to sample. The distribution is specified by its CDF. Super-constant
	* timing: the CDF table is ingested for every sample.
	*/

	size_t rndlen = 2 * n;
	uint16_t *rndvec = (uint16_t *)malloc(rndlen);
	if (rndvec == NULL) {
		return 0;
	}
	OQS_RAND_n(rand, (uint8_t *)rndvec, rndlen);

	size_t i, j;

	for (i = 0; i < n; ++i) {
		uint8_t sample = 0;
		uint16_t rnd = rndvec[i] >> 1; // drop the least significant bit
		uint8_t sign = rndvec[i] & 0x1; // pick the least significant bit

										// No need to compare with the last value.
		for (j = 0; j < cdf_table_len - 1; j++) {
			// Constant time comparison: 1 if LWE_CDF_TABLE[j] < rnd, 0 otherwise.
			// Critically uses the fact that LWE_CDF_TABLE[j] and rnd fit in 15 bits.
			sample += (uint16_t)(cdf_table[j] - rnd) >> 15;
		}
		// Assuming that sign is either 0 or 1, flips sample iff sign = 1
		s[i] = ((-sign) ^ sample) + sign;
	}

	memset(rndvec, 0, rndlen);
	free(rndvec);
	return 1;
}

int oqs_kex_lwe_okcn_sample_n(uint16_t *s, const size_t n, struct oqs_kex_lwe_okcn_params *params, OQS_RAND *rand) {

	switch (params->sampler_num) {
	case 8: {
		// have to copy cdf_table from uint16_t to uint8_t
		uint8_t *cdf_table_8 = malloc(params->cdf_table_len * sizeof(uint8_t));
		if (NULL == cdf_table_8) {
			return 0;
		}
		for (size_t i = 0; i < params->cdf_table_len; i++) {
			cdf_table_8[i] = (uint8_t)params->cdf_table[i];
		}
		int ret = lwe_sample_n_inverse_8(s, n, cdf_table_8, params->cdf_table_len, rand);
		free(cdf_table_8);
		return ret;
	}
	case 12:
		return lwe_sample_n_inverse_12(s, n, params->cdf_table, params->cdf_table_len, rand);
	case 16:
		return lwe_sample_n_inverse_16(s, n, params->cdf_table, params->cdf_table_len, rand);
	default:
		return 0;
	}

}


#define LWE_DIV_ROUNDUP(x, y) (((x) + (y)-1) / y)

// define parameters for "recommended" parameter set
#define PARAMS_N 712
#define PARAMS_NBAR 8
#define PARAMS_LOG2Q 14
#define PARAMS_Q (1 << PARAMS_LOG2Q)
#define PARAMS_EXTRACTED_BITS 4
#define PARAMS_KEY_BITS 256
#define PARAMS_STRIPE_STEP 8
#define PARAMS_SINGLE_HINT_BITS 8
#define PARAMS_REC_HINT_LENGTH LWE_DIV_ROUNDUP(PARAMS_NBAR * PARAMS_NBAR * PARAMS_SINGLE_HINT_BITS, 8)
// pre-process code to obtain "recommended" functions
#define MACRIFY(NAME) NAME ## _recommended

void oqs_kex_lwe_okcn_con_recommended(unsigned char *bob_rec, unsigned char *key, uint16_t *in) {
	int i;
	for (i = 0; i < PARAMS_NBAR * PARAMS_NBAR; i++) {
		bob_rec[i] = in[i] >> 2;
		in[i] >>= 10;  // drop least bits
	}
	oqs_kex_lwe_okcn_pack(key, PARAMS_KEY_BITS / 8, in, PARAMS_NBAR * PARAMS_NBAR, PARAMS_EXTRACTED_BITS);
}

void oqs_kex_lwe_okcn_rec_recommended(unsigned char *key, uint16_t *w, const unsigned char *hint) {
	int i;
	for (i = 0; i < PARAMS_NBAR * PARAMS_NBAR; i++) {
		w[i] = (w[i] - (((uint16_t)hint[i]) << 2) + 510) >> 10;
	}
	oqs_kex_lwe_okcn_pack(key, PARAMS_KEY_BITS / 8, w, PARAMS_NBAR * PARAMS_NBAR, PARAMS_EXTRACTED_BITS);
}

// Generate-and-multiply: generate A row-wise, multiply by s on the right.
int oqs_kex_lwe_okcn_mul_add_as_plus_e_on_the_fly_recommended(uint16_t *out, const uint16_t *s, const uint16_t *e, struct oqs_kex_lwe_okcn_params *params) {
	// A (N x N)
	// s,e (N x N_BAR)
	// out = A * s + e (N x N_BAR)

	int i, j, k;
	int ret = 0;
	uint16_t *a_row = NULL;
	uint16_t *s_transpose = NULL;

	for (i = 0; i < PARAMS_N; i++) {
		for (j = 0; j < PARAMS_NBAR; j++) {
			out[i * PARAMS_NBAR + j] = e[i * PARAMS_NBAR + j];
		}
	}

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
			out[i * PARAMS_NBAR + k] += sum;
			out[i * PARAMS_NBAR + k] %= PARAMS_Q;
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
int oqs_kex_lwe_okcn_mul_add_sa_plus_e_on_the_fly_recommended(uint16_t *out, const uint16_t *s, const uint16_t *e, struct oqs_kex_lwe_okcn_params *params) {
	// a (N x N)
	// s',e' (N_BAR x N)
	// out = s'a + e' (N_BAR x N)

	int i, j, k, kk;
	int ret = 0;
	uint16_t *a_cols = NULL;
	uint16_t *a_cols_t = NULL;

	for (i = 0; i < PARAMS_NBAR; i++) {
		for (j = 0; j < PARAMS_N; j++) {
			out[i * PARAMS_N + j] = e[i * PARAMS_N + j];
		}
	}

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
				out[i * PARAMS_N + kk + k] += sum;
				out[i * PARAMS_N + kk + k] %= PARAMS_Q;
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
void oqs_kex_lwe_okcn_mul_bs_recommended(uint16_t *out, const uint16_t *b, const uint16_t *s) {
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
			out[i * PARAMS_NBAR + j] %= PARAMS_Q;  // not really necessary since LWE_Q is a power of 2.
		}
	}
}

// multiply by s on the left
void oqs_kex_lwe_okcn_mul_add_sb_plus_e_recommended(uint16_t *out, const uint16_t *b, const uint16_t *s, const uint16_t *e) {
	// b (N x N_BAR)
	// s (N_BAR x N)
	// e (N_BAR x N_BAR)
	// out = sb + e
	int i, j, k;
	for (k = 0; k < PARAMS_NBAR; k++) {
		for (i = 0; i < PARAMS_NBAR; i++) {
			out[k * PARAMS_NBAR + i] = e[k * PARAMS_NBAR + i];
			for (j = 0; j < PARAMS_N; j++) {
				out[k * PARAMS_NBAR + i] += s[k * PARAMS_N + j] * b[j * PARAMS_NBAR + i];
			}
			out[k * PARAMS_NBAR + i] %= PARAMS_Q;  // not really necessary since LWE_Q is a power of 2.
		}
	}
}

// undefine macros to avoid any confusion later
#undef PARAMS_SINGLE_HINT_BITS
#undef PARAMS_N
#undef PARAMS_NBAR
#undef PARAMS_LOG2Q
#undef PARAMS_Q
#undef PARAMS_EXTRACTED_BITS
#undef PARAMS_KEY_BITS
#undef PARAMS_STRIPE_STEP
#undef PARAMS_REC_HINT_LENGTH
#undef MACRIFY
