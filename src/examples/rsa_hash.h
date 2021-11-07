/*
 *  Copyright (C) 2021 - This file is part of libecc project
 *
 *  Authors:
 *      Ryad BENADJILA <ryadbenadjila@gmail.com>
 *      Arnaud EBALARD <arnaud.ebalard@ssi.gouv.fr>
 *
 *  This software is licensed under a dual BSD and GPL v2 license.
 *  See LICENSE file at the root folder of the project.
 */
#ifndef __RSA_HASH_H__
#define __RSA_HASH_H__


/*
 * NOTE: although we only need libarith for RSA as we
 * manipulate a ring of integers, we include libsig for
 * the hash algorithms.
 */
#include "libec.h"

/****************************************************/
/*
 * 32-bit integer manipulation macros (big endian)
 */
#ifndef GET_UINT32_BE
#define GET_UINT32_BE(n, b, i)			  \
do {						    \
	(n) =     ( ((u32) (b)[(i)    ]) << 24 )   \
		| ( ((u32) (b)[(i) + 1]) << 16 )	\
		| ( ((u32) (b)[(i) + 2]) <<  8 )	\
		| ( ((u32) (b)[(i) + 3])       );       \
} while( 0 )
#endif
#ifndef GET_UINT32_LE
#define GET_UINT32_LE(n, b, i)			  \
do {						    \
	(n) =     ( ((u32) (b)[(i) + 3]) << 24 )   \
		| ( ((u32) (b)[(i) + 2]) << 16 )	\
		| ( ((u32) (b)[(i) + 1]) <<  8 )	\
		| ( ((u32) (b)[(i)    ])       );       \
} while( 0 )
#endif


#ifndef PUT_UINT32_BE
#define PUT_UINT32_BE(n, b, i)		  \
do {					    \
	(b)[(i)    ] = (u8) ( (n) >> 24 );      \
	(b)[(i) + 1] = (u8) ( (n) >> 16 );      \
	(b)[(i) + 2] = (u8) ( (n) >>  8 );      \
	(b)[(i) + 3] = (u8) ( (n)       );      \
} while( 0 )
#endif

#ifndef PUT_UINT32_LE
#define PUT_UINT32_LE(n, b, i)		  \
do {					    \
	(b)[(i) + 3] = (u8) ( (n) >> 24 );      \
	(b)[(i) + 2] = (u8) ( (n) >> 16 );      \
	(b)[(i) + 1] = (u8) ( (n) >>  8 );      \
	(b)[(i)    ] = (u8) ( (n)       );      \
} while( 0 )
#endif

#define SHA1_STATE_SIZE   5
#define SHA1_BLOCK_SIZE   64
#define SHA1_DIGEST_SIZE  20
#define SHA1_DIGEST_SIZE_BITS  160

#define SHA1_HASH_MAGIC ((word_t)(0x1120387132308110ULL))
#define SHA1_HASH_CHECK_INITIALIZED(A, ret, err) \
	MUST_HAVE((((void *)(A)) != NULL) && ((A)->magic == SHA1_HASH_MAGIC), ret, err)

#define ROTL_SHA1(x, n)      ((((u32)(x)) << (n)) | (((u32)(x)) >> (32-(n))))

/* All the innder SHA-1 operations */
#define K1	0x5a827999
#define K2	0x6ed9eba1
#define K3	0x8f1bbcdc
#define K4	0xca62c1d6

#define F1(x, y, z)   ((z) ^ ((x) & ((y) ^ (z))))
#define F2(x, y, z)   ((x) ^ (y) ^ (z))
#define F3(x, y, z)   (((x) & (y)) | ((z) & ((x) | (y))))
#define F4(x, y, z)   ((x) ^ (y) ^ (z))

#define SHA1_EXPAND(W, i) (W[i & 15] = ROTL_SHA1((W[i & 15] ^ W[(i - 14) & 15] ^ W[(i - 8) & 15] ^ W[(i - 3) & 15]), 1))

#define SHA1_SUBROUND(a, b, c, d, e, F, K, data) do { \
	u32 A_, B_, C_, D_, E_; \
	A_ = (e + ROTL_SHA1(a, 5) + F(b, c, d) + K + data); \
	B_ = a; \
	C_ = ROTL_SHA1(b, 30); \
	D_ = c; \
	E_ = d; \
	/**/ \
	a = A_; b = B_; c = C_; d = D_; e = E_; \
} while(0)

typedef struct {
	/* Number of bytes processed */
	u64 sha1_total;
	/* Internal state */
	u32 sha1_state[SHA1_STATE_SIZE];
	/* Internal buffer to handle updates in a block */
	u8 sha1_buffer[SHA1_BLOCK_SIZE];
	/* Initialization magic value */
	word_t magic;
} sha1_context;

/* SHA-2 core processing. Returns 0 on success, -1 on error. */
ATTRIBUTE_WARN_UNUSED_RET static inline int sha1_process(sha1_context *ctx,
			   const u8 data[SHA1_BLOCK_SIZE])
{
	u32 A, B, C, D, E;
	u32 W[16];
	int ret;
	unsigned int i;

	MUST_HAVE((data != NULL), ret, err);
	SHA1_HASH_CHECK_INITIALIZED(ctx, ret, err);

	/* Init our inner variables */
	A = ctx->sha1_state[0];
	B = ctx->sha1_state[1];
	C = ctx->sha1_state[2];
	D = ctx->sha1_state[3];
	E = ctx->sha1_state[4];

	/* Load data */
	for (i = 0; i < 16; i++) {
		if(arch_is_big_endian()){
			GET_UINT32_LE(W[i], data, (4 * i));
		}
		else{
			GET_UINT32_BE(W[i], data, (4 * i));
		}
	}
	for (i = 0; i < 80; i++) {
		if(i <= 15){
			SHA1_SUBROUND(A, B, C, D, E, F1, K1, W[i]);
		}
		else if((i >= 16) && (i <= 19)){
			SHA1_SUBROUND(A, B, C, D, E, F1, K1, SHA1_EXPAND(W, i));
		}
		else if((i >= 20) && (i <= 39)){
			SHA1_SUBROUND(A, B, C, D, E, F2, K2, SHA1_EXPAND(W, i));
		}
		else if((i >= 40) && (i <= 59)){
			SHA1_SUBROUND(A, B, C, D, E, F3, K3, SHA1_EXPAND(W, i));
		}
		else{
			SHA1_SUBROUND(A, B, C, D, E, F4, K4, SHA1_EXPAND(W, i));
		}
	}

	/* Update state */
	ctx->sha1_state[0] += A;
	ctx->sha1_state[1] += B;
	ctx->sha1_state[2] += C;
	ctx->sha1_state[3] += D;
	ctx->sha1_state[4] += E;

	ret = 0;

err:
	return ret;
}

/* Init hash function. Returns 0 on success, -1 on error. */
ATTRIBUTE_WARN_UNUSED_RET static int sha1_init(sha1_context *ctx)
{
	int ret;

	MUST_HAVE((ctx != NULL), ret, err);

	ctx->sha1_total = 0;
	ctx->sha1_state[0] = 0x67452301;
	ctx->sha1_state[1] = 0xefcdab89;
	ctx->sha1_state[2] = 0x98badcfe;
	ctx->sha1_state[3] = 0x10325476;
	ctx->sha1_state[4] = 0xc3d2e1f0;

	/* Tell that we are initialized */
	ctx->magic = SHA1_HASH_MAGIC;

	ret = 0;

err:
	return ret;
}

ATTRIBUTE_WARN_UNUSED_RET static inline int sha1_update(sha1_context *ctx, const u8 *input, u32 ilen)
{
	const u8 *data_ptr = input;
	u32 remain_ilen = ilen;
	u16 fill;
	u8 left;
	int ret;

	MUST_HAVE((input != NULL), ret, err);
	SHA1_HASH_CHECK_INITIALIZED(ctx, ret, err);

	/* Nothing to process, return */
	if (ilen == 0) {
		ret = 0;
		goto err;
	}

	/* Get what's left in our local buffer */
	left = (ctx->sha1_total & 0x3F);
	fill = (SHA1_BLOCK_SIZE - left);

	ctx->sha1_total += ilen;

	if ((left > 0) && (remain_ilen >= fill)) {
		/* Copy data at the end of the buffer */
		ret = local_memcpy(ctx->sha1_buffer + left, data_ptr, fill); EG(ret, err);
		ret = sha1_process(ctx, ctx->sha1_buffer); EG(ret, err);
		data_ptr += fill;
		remain_ilen -= fill;
		left = 0;
	}

	while (remain_ilen >= SHA1_BLOCK_SIZE) {
		ret = sha1_process(ctx, data_ptr); EG(ret, err);
		data_ptr += SHA1_BLOCK_SIZE;
		remain_ilen -= SHA1_BLOCK_SIZE;
	}

	if (remain_ilen > 0) {
		ret = local_memcpy(ctx->sha1_buffer + left, data_ptr, remain_ilen); EG(ret, err);
	}

	ret = 0;

err:
	return ret;
}

/* Finalize. Returns 0 on success, -1 on error.*/
ATTRIBUTE_WARN_UNUSED_RET static inline int sha1_final(sha1_context *ctx, u8 output[SHA1_DIGEST_SIZE])
{
	unsigned int block_present = 0;
	u8 last_padded_block[2 * SHA1_BLOCK_SIZE];
	int ret;

	MUST_HAVE((output != NULL), ret, err);
	SHA1_HASH_CHECK_INITIALIZED(ctx, ret, err);

	/* Fill in our last block with zeroes */
	ret = local_memset(last_padded_block, 0, sizeof(last_padded_block)); EG(ret, err);

	/* This is our final step, so we proceed with the padding */
	block_present = ctx->sha1_total % SHA1_BLOCK_SIZE;
	if (block_present != 0) {
		/* Copy what's left in our temporary context buffer */
		ret = local_memcpy(last_padded_block, ctx->sha1_buffer,
			     block_present); EG(ret, err);
	}

	/* Put the 0x80 byte, beginning of padding  */
	last_padded_block[block_present] = 0x80;

	/* Handle possible additional block */
	if (block_present > (SHA1_BLOCK_SIZE - 1 - sizeof(u64))) {
		/* We need an additional block */
		PUT_UINT64_BE(8 * ctx->sha1_total, last_padded_block,
			      (2 * SHA1_BLOCK_SIZE) - sizeof(u64));
		ret = sha1_process(ctx, last_padded_block); EG(ret, err);
		ret = sha1_process(ctx, last_padded_block + SHA1_BLOCK_SIZE); EG(ret, err);
	} else {
		/* We do not need an additional block */
		PUT_UINT64_BE(8 * ctx->sha1_total, last_padded_block,
			      SHA1_BLOCK_SIZE - sizeof(u64));
		ret = sha1_process(ctx, last_padded_block); EG(ret, err);
	}

	/* Output the hash result */
	PUT_UINT32_BE(ctx->sha1_state[0], output, 0);
	PUT_UINT32_BE(ctx->sha1_state[1], output, 4);
	PUT_UINT32_BE(ctx->sha1_state[2], output, 8);
	PUT_UINT32_BE(ctx->sha1_state[3], output, 12);
	PUT_UINT32_BE(ctx->sha1_state[4], output, 16);

	/* Tell that we are uninitialized */
	ctx->magic = WORD(0);

	ret = 0;

err:
	return ret;
}


/*
 * Scattered version performing init/update/finalize on a vector of buffers
 * 'inputs' with the length of each buffer passed via 'ilens'. The function
 * loops on pointers in 'inputs' until it finds a NULL pointer. The function
 * returns 0 on success, -1 on error.
 */
ATTRIBUTE_WARN_UNUSED_RET static inline int sha1_scattered(const u8 **inputs, const u32 *ilens,
		      u8 output[SHA1_DIGEST_SIZE])
{
	sha1_context ctx;
	int ret, pos = 0;

	MUST_HAVE((inputs != NULL) && (ilens != NULL) && (output != NULL), ret, err);

	ret = sha1_init(&ctx); EG(ret, err);

	while (inputs[pos] != NULL) {
		ret = sha1_update(&ctx, inputs[pos], ilens[pos]); EG(ret, err);
		pos += 1;
	}

	ret = sha1_final(&ctx, output);

err:
	return ret;
}

/*
 * Single call version performing init/update/final on given input.
 * Returns 0 on success, -1 on error.
 */
ATTRIBUTE_WARN_UNUSED_RET static inline int sha1(const u8 *input, u32 ilen, u8 output[SHA1_DIGEST_SIZE])
{
	sha1_context ctx;
	int ret;

	ret = sha1_init(&ctx); EG(ret, err);
	ret = sha1_update(&ctx, input, ilen); EG(ret, err);
	ret = sha1_final(&ctx, output);

err:
	return ret;
}

/****************************************************/
/****************************************************/
/****************************************************/
typedef enum {
	/* libecc native hashes */
	RSA_SHA224 = 0,
	RSA_SHA256 = 1,
	RSA_SHA384 = 2,
	RSA_SHA512 = 3,
	RSA_SHA512_224 = 4,
	RSA_SHA512_256 = 5,
	RSA_SHA3_224 = 6,
	RSA_SHA3_256 = 7,
	RSA_SHA3_384 = 8,
	RSA_SHA3_512 = 9,
	RSA_SM3 = 10,
	RSA_STREEBOG256 = 11,
	RSA_STREEBOG512 = 12,
	RSA_SHAKE256 = 13,
	/* Deprecated hashes nor supported by libecc
	 * (for security reasons).
	 */
	RSA_MD5 = 14,
	RSA_SHA1 = 15,
	RSA_NO_HASH = 16,
} rsa_hash_alg_type;

ATTRIBUTE_WARN_UNUSED_RET int rsa_get_hash_sizes(rsa_hash_alg_type rsa_hash_type, u8 *hlen, u8 *block_size);
ATTRIBUTE_WARN_UNUSED_RET int rsa_digestinfo_from_hash(rsa_hash_alg_type rsa_hash_type, u8 *digestinfo, u32 *digestinfo_len);
ATTRIBUTE_WARN_UNUSED_RET int rsa_hfunc_scattered(const u8 **input, const u32 *ilen, u8 *digest, rsa_hash_alg_type rsa_hash_type);

#endif /* __RSA_HASH_H__ */