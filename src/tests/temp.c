#include "../libsig.h"
#include "ckb_syscalls.h"

#ifdef WITH_STDLIB
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#endif

#define HDR_MAGIC    0x34215609
/* Max stack working buffer size */
#define MAX_BUF_LEN     8192

#include "ec_secp256r1_core.h"

int main()
{
    u8 msg[MAX_BUF_LEN] = {72,101,108,108,111,32,119,111,114,108,100,33,10,10};
    u8 sig[MAX_BUF_LEN] = {181,218,4,206,50,182,120,98,204,239,233,229,173,215,0,52,72,48,68,167,122,10,4,219,2,180,50,244,138,101,206,23,225,248,191,56,213,141,29,239,125,247,82,208,63,140,186,128,252,144,20,82,55,79,246,1,128,43,25,143,32,146,19,77,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    u8 pk[MAX_BUF_LEN] = {0,1,4,179,234,171,173,79,197,190,22,184,10,118,196,150,172,104,79,14,10,206,20,107,114,234,124,22,107,215,211,216,255,23,228,30,3,120,40,12,72,45,102,150,198,94,156,96,55,247,51,2,85,166,248,190,104,245,84,101,88,62,40,58,219,93,108,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

    u8 msg_len = 14;
    return verify_secp256r1_once(sig, pk, msg, msg_len);
}