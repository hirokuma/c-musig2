#ifndef COMMON_H
#define COMMON_H

#include <stddef.h>
#include <stdint.h>

#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_musig.h>

#define ARRAY_SIZE(a) (sizeof(a)/sizeof(a[0]))

#define SIGNER_NUM  (3)


void dump(const uint8_t *data, size_t len);
int aggPubKey(
    secp256k1_xonly_pubkey *agg_pk,
    secp256k1_musig_keyagg_cache *cache,
    const uint8_t *pubkeys[],
    int keyNum);

#endif /* COMMON_H */
