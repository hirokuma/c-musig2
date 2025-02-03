#ifndef SIGNER_H
#define SIGNER_H

#include <stdint.h>

#include "libwally-core/include/wally_crypto.h"


int signerGetPubkey(uint8_t pub[EC_PUBLIC_KEY_LEN], int signerId);
int signerGetPubNonce(uint8_t nonce[66], int signerId, const uint8_t *sigHash);
int signerGetPartialSign(
    uint8_t sign[32],
    int signerId,
    const uint8_t *sigHash,
    const uint8_t aggNonce[66],
    const uint8_t *pubkeys[],
    int keyNum);

#endif /* SIGNER_H */
