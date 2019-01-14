#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <oqs/rand.h>

#include "local.h"

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
	OQS_RAND_n(rand, (uint8_t *) rndvec, rndlen);

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