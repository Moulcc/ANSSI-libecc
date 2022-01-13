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

	u8 buff[MAX_BUF_LEN] = {104,101,108,108,111,10};
	pub_key_buf_len = 99;
	u8 pub_key_buf[MAX_BUF_LEN] = {0,1,4,120,248,235,124,209,26,120,187,156,113,36,4,67,43,44,114,207,152,247,126,154,167,156,214,252,63,129,93,160,222,117,216,122,94,4,172,119,17,22,125,66,255,186,45,81,101,249,7,136,184,106,255,99,74,89,132,98,116,186,124,25,216,70,72,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};		
	u8 sig[MAX_BUF_LEN] = {196,153,224,49,197,121,95,234,28,187,82,206,115,76,111,169,170,218,196,219,85,218,126,204,121,61,139,230,117,229,255,79,191,82,76,157,70,26,164,185,169,193,220,11,82,112,218,91,224,228,28,43,158,165,186,188,253,254,222,233,192,28,158,148,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};	
	

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
	raw_data_len = 6;
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

		to_read = 6;
		read = 6;

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
	argv[4] = "SHA3_512";
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

	if (verify_bin_file(argv[2], argv[3], argv[4], adata, adata_len))
		return -1;
	else 
		return 0;
}



