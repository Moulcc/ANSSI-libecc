#include "../libsig.h"

int verify_secp256r1_once(u8* sig, u8* pk, u8* msg, u8 msg_len);

typedef enum {
    SECP256R1_SUCCESS = 0,
    SECP256R1_BAD_ENCODING = 1,
    SECP256R1_POINT_NOT_ON_CURVE = 2,
    SECP256R1_POINT_NOT_IN_GROUP = 3,
    SECP256R1_AGGR_TYPE_MISMATCH = 4,
    SECP256R1_VERIFY_FAIL = 5,
    SECP256R1_PK_IS_INFINITY = 6,
} SECP256R1_ERROR;
