#if defined(WINDOWS)
#define UNUSED
#else
#define UNUSED __attribute__ ((unused))
#endif

#include <stdlib.h>
#include <string.h>
#if !defined(WINDOWS)
#include <strings.h>
#include <unistd.h>
#endif

#include <oqs/kex.h>
#include <oqs/rand.h>

#include "kex_lwr_okcn.h"
#include "local.h"

#define LWR_DIV_ROUNDUP(x, y) (((x) + (y)-1) / y)

#include <stdio.h>

OQS_KEX *OQS_KEX_lwr_okcn_new(OQS_RAND *rand, const uint8_t *seed, const size_t seed_len, const char *named_parameters) {

	OQS_KEX *k;
	struct oqs_kex_lwr_okcn_params *params;

	if ((seed_len == 0) || (seed == NULL)) {
		return NULL;
	}

	k = malloc(sizeof(OQS_KEX));
	if (k == NULL) {
		goto err;
	}
	k->named_parameters = NULL;
	k->method_name = NULL;

	k->params = malloc(sizeof(struct oqs_kex_lwr_okcn_params));
	if (NULL == k->params) {
		goto err;
	}
	params = (struct oqs_kex_lwr_okcn_params *) k->params;
	params->cdf_table = NULL;
	params->seed = NULL;
	params->param_name = NULL;

	k->rand = rand;
	k->ctx = NULL;
	k->alice_priv_free = &OQS_KEX_lwr_okcn_alice_priv_free;
	k->free = &OQS_KEX_lwr_okcn_free;

	if (strcmp(named_parameters, "recommended") == 0) {

		k->alice_0 = &OQS_KEX_lwr_okcn_alice_0_recommended;
		k->bob = &OQS_KEX_lwr_okcn_bob_recommended;
		k->alice_1 = &OQS_KEX_lwr_okcn_alice_1_recommended;

		k->method_name = strdup("LWR OKCN recommended");
		if (NULL == k->method_name) {
			goto err;
		}
		k->estimated_classical_security = 147;
		k->estimated_quantum_security = 134;
		k->named_parameters = strdup(named_parameters);
		if (k->named_parameters == NULL) {
			goto err;
		}

		params->seed = malloc(seed_len);
		if (NULL == params->seed) {
			goto err;
		}
		memcpy(params->seed, seed, seed_len);
		params->seed_len = seed_len;
		params->param_name = strdup("recommended");
		if (NULL == params->param_name) {
			goto err;
		}
		params->log2_q = 15;
		params->log2_p = 12;
		params->q = 1 << params->log2_q;
		params->p = 1 << params->log2_p;
		params->n = 680;
		params->extracted_bits = 4;
		params->nbar = 8;
		params->key_bits = 256;
        params->single_hint_len = 8;
		params->rec_hint_len = LWR_DIV_ROUNDUP(params->nbar * params->nbar * params->single_hint_len, 8);
		params->pub_len = LWR_DIV_ROUNDUP(params->n * params->nbar * params->log2_p, 8);
		params->stripe_step = 8;
		params->sampler_num = 16;
		params->cdf_table_len = 6;
		params->cdf_table = malloc(params->cdf_table_len * sizeof(uint16_t));
		if (NULL == params->cdf_table) {
			goto err;
		}
		uint16_t cdf_table_tmp[6] = {9785, 24577, 30960, 32530, 32750, 32767};
		memcpy(params->cdf_table, cdf_table_tmp, sizeof(cdf_table_tmp));
	} else {

		goto err;

	}

	return k;

err:
	if (k) {
		if (k->params) {
			free(params->cdf_table);
			free(params->seed);
			free(params->param_name);
			free(k->params);
		}
		free(k->named_parameters);
		free(k->method_name);
		free(k);
	}
	return NULL;

}

// pre-process code to obtain "recommended" functions
#define MACRIFY(NAME) NAME ## _recommended
#include "kex_lwr_okcn_macrify.c"
// undefine macros to avoid any confusion later
#undef MACRIFY

void OQS_KEX_lwr_okcn_alice_priv_free(UNUSED OQS_KEX *k, void *alice_priv) {
	if (alice_priv) {
		free(alice_priv);
	}
}

void OQS_KEX_lwr_okcn_free(OQS_KEX *k) {
	if (!k) {
		return;
	}
	if (k->params) {
		struct oqs_kex_lwr_okcn_params *params = (struct oqs_kex_lwr_okcn_params *) k->params;
		free(params->cdf_table);
		params->cdf_table = NULL;
		free(params->seed);
		params->seed = NULL;
		free(params->param_name);
		params->param_name = NULL;
		free(k->params);
		k->params = NULL;
	}
	free(k->named_parameters);
	k->named_parameters = NULL;
	free(k->method_name);
	k->method_name = NULL;
	free(k);
}
