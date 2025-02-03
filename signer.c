#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/random.h>

#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_musig.h>
#include <secp256k1_schnorrsig.h>

#include "libwally-core/include/wally_core.h"
#include "libwally-core/include/wally_crypto.h"
#include "libwally-core/include/wally_address.h"
#include "libwally-core/include/wally_map.h"
#include "libwally-core/include/wally_script.h"

#include "common.h"
#include "signer.h"

static const uint8_t privateKey1[] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
};
static const uint8_t privateKey2[] = {
    0x02, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
};
static const uint8_t privateKey3[] = {
    0x03, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
};
static const uint8_t *privateKeys[SIGNER_NUM] = {
    privateKey1,
    privateKey2,
    privateKey3,
};


static int signerKeyPair(secp256k1_keypair* keypair, int signerId)
{
    const struct secp256k1_context_struct *ctx = wally_get_secp_context();

    const uint8_t *seckey = privateKeys[signerId];
    if (!secp256k1_keypair_create(ctx, keypair, seckey)) {
        return 1;
    }
    return 0;
}


// round 0: get 33byte pubkey
int signerGetPubkey(uint8_t pub[EC_PUBLIC_KEY_LEN], int signerId)
{
    const uint8_t *seckey = privateKeys[signerId];

    int rc;

    rc = wally_ec_public_key_from_private_key(
        seckey, EC_PRIVATE_KEY_LEN,
        pub, EC_PUBLIC_KEY_LEN);
    if (rc != WALLY_OK) {
        printf("error: wally_ec_public_key_from_private_key fail: %d\n", rc);
        return 1;
    }
    printf("pub[%d]: ", signerId);
    dump(pub, EC_PUBLIC_KEY_LEN);

    return 0;
}



static int calcNonce(
    secp256k1_keypair *keypair,
    secp256k1_musig_secnonce *secnonce,
    secp256k1_musig_pubnonce *pubnonce,
    const uint8_t *sigHash,
    int signerId)
{
    const struct secp256k1_context_struct *ctx = wally_get_secp_context();

    // dummy
    uint8_t session_secrand[32];
    memcpy(session_secrand, privateKeys[signerId], sizeof(session_secrand));

    signerKeyPair(keypair, signerId);
    secp256k1_pubkey pubkey;
    if (!secp256k1_keypair_pub(ctx, &pubkey, keypair)) {
        printf("fail secp256k1_keypair_pub %d\n", signerId);
        return 1;
    }

    unsigned char seckey[32];
    if (!secp256k1_keypair_sec(ctx, seckey, keypair)) {
        printf("fail secp256k1_keypair_sec %d\n", signerId);
        return 1;
    }
    if (!secp256k1_musig_nonce_gen(
            ctx,
            secnonce,
            pubnonce,
            session_secrand,
            seckey,
            &pubkey,
            sigHash,
            NULL,
            NULL)) {
        printf("fail secp256k1_musig_nonce_gen %d\n", signerId);
        return 1;
    }

    return 0;
}

// round 1: get public nonce
int signerGetPubNonce(uint8_t nonce[66], int signerId, const uint8_t *sigHash)
{
    const struct secp256k1_context_struct *ctx = wally_get_secp_context();

    secp256k1_keypair keypair;
    secp256k1_musig_secnonce secnonce;
    secp256k1_musig_pubnonce pubnonce;
    int rc = calcNonce(&keypair, &secnonce, &pubnonce, sigHash, signerId);
    if (rc != 0) {
        printf("fail calcNonce %d\n", signerId);
        return 1;
    }

    if (!secp256k1_musig_pubnonce_serialize(ctx, nonce, &pubnonce)) {
        printf("fail secp256k1_musig_pubnonce_serialize %d\n", signerId);
        return 1;
    }

    return 0;
}

// round 2: get partial sign
int signerGetPartialSign(
    uint8_t sign[32],
    int signerId,
    const uint8_t *sigHash,
    const uint8_t aggNonce[66],
    const uint8_t *pubkeys[],
    int keyNum)
{
    const struct secp256k1_context_struct *ctx = wally_get_secp_context();

    secp256k1_musig_aggnonce agg_pubnonce;
    if (!secp256k1_musig_aggnonce_parse(ctx, &agg_pubnonce, aggNonce)) {
        printf("fail secp256k1_musig_aggnonce_parse %d\n", signerId);
        return 1;
    }

    secp256k1_xonly_pubkey agg_pk;
    secp256k1_musig_keyagg_cache cache;
    if (aggPubKey(&agg_pk, &cache, pubkeys, keyNum)) {
        printf("error: aggPubKey fail %d\n", signerId);
        return 1;
    }

    secp256k1_keypair keypair;
    secp256k1_musig_secnonce secnonce;
    secp256k1_musig_pubnonce pubnonce;
    int rc = calcNonce(&keypair, &secnonce, &pubnonce, sigHash, signerId);
    if (rc != 0) {
        printf("fail calcNonce %d\n", signerId);
        return 1;
    }

    secp256k1_musig_session session;
    if (!secp256k1_musig_nonce_process(ctx, &session, &agg_pubnonce, sigHash, &cache)) {
        return 1;
    }
    secp256k1_musig_partial_sig partial_sig;
    if (!secp256k1_musig_partial_sign(ctx, &partial_sig, &secnonce, &keypair, &cache, &session)) {
        return 1;
    }

    if (!secp256k1_musig_partial_sig_serialize(ctx, sign, &partial_sig)) {
        printf("fail secp256k1_musig_partial_sig_serialize %d\n", signerId);
        return 1;
    }

    return 0;
}
