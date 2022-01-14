#include "../libsig.h"
#include "ckb_syscalls.h"

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


/*
 * Verify signature data from file with appended signature
 */
static int verify_bin_file(const char *ec_name, const char *ec_sig_name, const char *hash_algorithm,
//		const char *in_fname, const char *in_key_fname, const char *in_sig_fname, 
		const char *adata, u16 adata_len)
{
	struct ec_verify_context verif_ctx;
	const ec_str_params *ec_str_p;
	ec_sig_alg_type sig_type;
	hash_alg_type hash_type;
	u8 siglen;
	size_t read, to_read;
	u8 pub_key_buf_len;
	size_t raw_data_len;
	ec_pub_key pub_key;
	ec_params params;
	size_t exp_len;
	int ret, eof;

	u8 buff[MAX_BUF_LEN] = {72,101,108,108,111,32,119,111,114,108,100,33,10,10};
	pub_key_buf_len = 99;
	u8 sig[MAX_BUF_LEN] = {181,218,4,206,50,182,120,98,204,239,233,229,173,215,0,52,72,48,68,167,122,10,4,219,2,180,50,244,138,101,206,23,225,248,191,56,213,141,29,239,125,247,82,208,63,140,186,128,252,144,20,82,55,79,246,1,128,43,25,143,32,146,19,77,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
	u8 pub_key_buf[MAX_BUF_LEN] = {0,1,4,179,234,171,173,79,197,190,22,184,10,118,196,150,172,104,79,14,10,206,20,107,114,234,124,22,107,215,211,216,255,23,228,30,3,120,40,12,72,45,102,150,198,94,156,96,55,247,51,2,85,166,248,190,104,245,84,101,88,62,40,58,219,93,108,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
	MUST_HAVE(ec_name != NULL);

	/************************************/
	/* Get parameters from pretty names */
	if (string_to_params(ec_name, ec_sig_name, &sig_type, &ec_str_p,
			     hash_algorithm, &hash_type)) {
		goto err;
	}

	/* Import the parameters */
	import_params(&params, ec_str_p);

	ret = ec_get_sig_len(&params, sig_type, hash_type, &siglen);
	if (ret) {
		goto err;
	}

	ret = ec_structured_pub_key_import_from_buf(&pub_key, &params,
						    pub_key_buf,
						    pub_key_buf_len, sig_type);	
	if (ret) {
		goto err;
	}

	/* Let's first get file size */
	raw_data_len = 14;
	to_read = 64;
	siglen = (u8)to_read;

	/* Read the raw signature from the signature file */
	read = 64;
	exp_len = raw_data_len;

	/*
	 * ... and read file content chunk by chunk to compute signature
	 */
	ret = ec_verify_init(&verif_ctx, &pub_key, sig, siglen,
			     sig_type, hash_type,(const u8*)adata, adata_len);
	if (ret) {
		goto err;
	}


	eof = 0;
	while (exp_len && !eof) {

		to_read = 14;
		read = 14;

		if (read > exp_len) {
			/* we read more than expected: leave! */
			break;
		}

		exp_len -= read;

		ret = ec_verify_update(&verif_ctx, buff, (u32)read);
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

int main()
{
	char* argv[9];
	
	argv[2] = "SECP256R1";
	argv[3] = "ECDSA";
	argv[4] = "SHA256";
//	argv[5] = "hello.txt";
//	argv[6] = "keypair_public_key.bin";
//	argv[7] = "sig.bin";
	
	/* Verify something ------------------------------
		*
		* arg1 = curve name ("frp256v1", ...)
		* arg2 = signature algorithm type ("ECDSA", "ECKCDSA", ...)
		* arg3 = hash algorithm type ("SHA256", "SHA512", ...)
		* arg4 = input file to verify
		* arg5 = input file with the public key
		* arg6 = input file containing the signature
		* arg7 (optional) = ancillary data to be used
		*/

	const char *adata = NULL;
	u16 adata_len = 0;

	return verify_bin_file(argv[2], argv[3], argv[4], adata, adata_len);
}



