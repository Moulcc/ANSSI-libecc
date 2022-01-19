#include "../libsig.h"
//#include "ckb_syscalls.h"

#ifdef WITH_STDLIB
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#endif

#define HDR_MAGIC	 0x34215609

/* Max stack working buffer size */
#define MAX_BUF_LEN		8192

static int string_to_params(const char *ec_name, const char *ec_sig_name,
			    ec_sig_alg_type * sig_type,
			    const ec_str_params ** ec_str_p,
			    const char *hash_name, hash_alg_type * hash_type)
{
	const ec_str_params *curve_params;
	const ec_sig_mapping *sm;
	const hash_mapping *hm;
	u32 curve_name_len;

	if (sig_type != NULL) {
		/* Get sig type from signature alg name */
		sm = get_sig_by_name(ec_sig_name);
		if (!sm) {
			goto err;
		}
		*sig_type = sm->type;
	}

	if (ec_str_p != NULL) {
		/* Get curve params from curve name */
		curve_name_len = local_strlen((const char *)ec_name) + 1;
		if(curve_name_len > 255){
			/* Sanity check */
			goto err;
		}
		curve_params = ec_get_curve_params_by_name((const u8 *)ec_name,
							   (u8)curve_name_len);
		if (!curve_params) {
			goto err;
		}
		*ec_str_p = curve_params;
	}

	if (hash_type != NULL) {
		/* Get hash type from hash alg name */
		hm = get_hash_by_name(hash_name);
		if (!hm) {
			goto err;
		}
		*hash_type = hm->type;
	}

	return 0;

 err:
	return -1;
}


int verify_secp256r1_once(u8* sig, u8* pk, u8* msg, u8 msg_len) {
	struct ec_verify_context verif_ctx;
    const ec_str_params *ec_str_p;
    ec_sig_alg_type sig_type;
    hash_alg_type hash_type;
    u8 siglen;
    size_t read;
    u8 pub_key_buf_len;
    size_t raw_data_len;
    ec_pub_key pub_key;
    ec_params params;
    size_t exp_len;
    int ret, eof;

	char* base[3];
	base[0] = "SECP256R1";
	base[1] = "ECDSA";
	base[2] = "SHA256";
    const char *adata = NULL;
    u16 adata_len = 0;

	if (string_to_params(base[0], base[1], &sig_type, &ec_str_p,
                 base[2], &hash_type)) {
        goto err;
    }

	import_params(&params, ec_str_p);

    ret = ec_get_sig_len(&params, sig_type, hash_type, &siglen);
    if (ret) {
        goto err;
    }

	pub_key_buf_len = 99;
	ret = ec_structured_pub_key_import_from_buf(&pub_key, &params,
                            pk,
                            pub_key_buf_len, sig_type);
    if (ret) {
        goto err;
    }

	raw_data_len = msg_len;
	siglen = 64;
	exp_len = raw_data_len;

	ret = ec_verify_init(&verif_ctx, &pub_key, sig, siglen,
			sig_type, hash_type,(const u8*)adata, adata_len);
    if (ret) {
        goto err;
    }

	eof = 0;
	while (exp_len && !eof) {
		
		read = msg_len; // need check
		
		if (read > exp_len) {
            /* we read more than expected: leave! */
            break;
        }

        exp_len -= read;

        ret = ec_verify_update(&verif_ctx, msg, (u32)read);
        if (ret) {
            break;
        }
	}

    ret = ec_verify_finalize(&verif_ctx);
    if (ret) {
        goto err;
    }

    return ret;

 err:
    return -1;
}
