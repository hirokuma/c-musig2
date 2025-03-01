#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/random.h>

#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_musig.h>
#include <secp256k1_schnorrsig.h>

#include "wally_core.h"
#include "wally_crypto.h"
#include "wally_address.h"
#include "wally_map.h"
#include "wally_script.h"

#include "common.h"
#include "coodinator.h"
#include "signer.h"


static const uint8_t publicKey1[] = {
    0x03, 0x46, 0x46, 0xae, 0x50, 0x47, 0x31, 0x6b,
    0x42, 0x30, 0xd0, 0x08, 0x6c, 0x8a, 0xce, 0xc6,
    0x87, 0xf0, 0x0b, 0x1c, 0xd9, 0xd1, 0xdc, 0x63,
    0x4f, 0x6c, 0xb3, 0x58, 0xac, 0x0a, 0x9a, 0x8f,
    0xff,
};
static const uint8_t publicKey2[] = {
    0x02, 0xa0, 0x62, 0xcd, 0xf1, 0x72, 0x37, 0x05,
    0xcd, 0x5e, 0xeb, 0x0f, 0xca, 0x9a, 0x7f, 0x68,
    0xcd, 0x46, 0x2e, 0xb2, 0x7b, 0x50, 0x39, 0x35,
    0xd3, 0x5e, 0x12, 0x7a, 0x19, 0xa4, 0x23, 0x55,
    0xef,
};
static const uint8_t publicKey3[] = {
    0x02, 0x43, 0x0b, 0xd2, 0x70, 0xf7, 0xc7, 0xc4,
    0x45, 0x47, 0x03, 0xc2, 0xce, 0xcd, 0x1d, 0x61,
    0x2e, 0x38, 0x43, 0x7c, 0xec, 0x3a, 0x64, 0x0a,
    0x87, 0x45, 0x75, 0x7b, 0x55, 0x1d, 0x99, 0x67,
    0x10,
};
const uint8_t *publicKeys[SIGNER_NUM] = {
    publicKey1,
    publicKey2,
    publicKey3,
};


static const char ADDR_FAMILY[] = "bcrt";

// MuSigアドレスに 1BTC 送金
// static const char PREV_RAW_TX[] = "020000000001018360ad42ab3f977e731ceebb7a4d2d71a2cab99fc061896f574ebbfcede5191f0000000000fdffffff0200e1f505000000002251201243b9429e070edfedf0f3bd6c76ff17cefb9cb8c1860fa006d254cddcc9bb925b10102401000000225120d708833a11971d5963e7901fb64dbd295a207af7f01de244345315039115ae9b02473044022055511b902e0a66fa645a2a94f74d00a0d2ac7f0ae210db02ff8f7bf128caaf14022008002052b8998aa96a442dca932657832397e9f79b9514d29cd47a70bd7b23df012103db4907751ed268617f0aed49d96dc0dfbbb8163b915d2e0ca446b50761f9a0c084000000";
#define OUTPOINT_TXHASH { \
    0xb5, 0x1c, 0xb7, 0x60, 0x09, 0x87, 0x6c, 0x5f,\
    0x0f, 0xd9, 0xf7, 0x67, 0x8b, 0x02, 0xa6, 0x00,\
    0x45, 0xff, 0x17, 0xdc, 0x8e, 0x71, 0x7c, 0x03,\
    0x32, 0xb5, 0x85, 0x2e, 0x5e, 0xc8, 0x45, 0x00,\
}
static const uint32_t OUTPOINT_INDEX = 0;
static const uint64_t PREV_AMOUNT = 100000000UL;
static const uint8_t WITNESS_PROGRAM[] = {
    0x51, 0x20, 0x12, 0x43, 0xb9, 0x42, 0x9e, 0x07,
    0x0e, 0xdf, 0xed, 0xf0, 0xf3, 0xbd, 0x6c, 0x76,
    0xff, 0x17, 0xce, 0xfb, 0x9c, 0xb8, 0xc1, 0x86,
    0x0f, 0xa0, 0x06, 0xd2, 0x54, 0xcd, 0xdc, 0xc9,
    0xbb, 0x92,
};

// MuSigアドレスへの送金を手数料 0.00010000 BTC で別のアドレスに送金
static const char OUTADDR[] = "bcrt1q4kuqygeas3z2wu4ldsm28luzae5lhfck2hp85u";
static const uint64_t FEE = 10000UL;
static const uint64_t SENT_AMOUNT = PREV_AMOUNT - FEE;

// * regtestでの結果
// * session_secrand[i] は privateKeys[i] を使用
static const uint8_t AGG_PUBKEY[] = {
    0x12, 0x43, 0xb9, 0x42, 0x9e, 0x07, 0x0e, 0xdf,
    0xed, 0xf0, 0xf3, 0xbd, 0x6c, 0x76, 0xff, 0x17,
    0xce, 0xfb, 0x9c, 0xb8, 0xc1, 0x86, 0x0f, 0xa0,
    0x06, 0xd2, 0x54, 0xcd, 0xdc, 0xc9, 0xbb, 0x92,
};
static const char AGG_ADDR[] = "bcrt1pzfpmjs57qu8dlm0s7w7kcahlzl80h89ccxrqlgqx6f2vmhxfhwfqfs97n2";
static const uint8_t SIGHASH[] = {
    0xae, 0x7f, 0x51, 0x2d, 0xfd, 0x7f, 0x6e, 0x62,
    0xcd, 0xc5, 0xcc, 0x3c, 0xea, 0x35, 0x0d, 0x60,
    0x9c, 0xf7, 0x7d, 0x43, 0x28, 0x84, 0xe9, 0x58,
    0xca, 0xd0, 0x29, 0x2a, 0xec, 0x64, 0xd6, 0xd4,
};
static const uint8_t SIG[] = {
    0x08, 0x36, 0xe5, 0xbb, 0x73, 0x3c, 0xfb, 0x11,
    0x03, 0x66, 0x11, 0x55, 0x8e, 0x30, 0x77, 0x2b,
    0x16, 0x99, 0x84, 0x1a, 0xc9, 0x4b, 0xc4, 0x23,
    0x51, 0x69, 0x6d, 0xed, 0xab, 0x5b, 0x5b, 0x5b,
    0xbc, 0xbe, 0x46, 0x83, 0xb5, 0x01, 0x7a, 0xa6,
    0x98, 0xa8, 0x45, 0x93, 0x28, 0x17, 0x48, 0xd1,
    0xf4, 0x1e, 0xa1, 0x90, 0x8d, 0x65, 0x81, 0x23,
    0xf9, 0x70, 0x41, 0x98, 0x13, 0xc5, 0x20, 0x0e,
};
static const uint8_t OUTPUT_RAW_TX[] = {
    0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0xb5,
    0x1c, 0xb7, 0x60, 0x09, 0x87, 0x6c, 0x5f, 0x0f,
    0xd9, 0xf7, 0x67, 0x8b, 0x02, 0xa6, 0x00, 0x45,
    0xff, 0x17, 0xdc, 0x8e, 0x71, 0x7c, 0x03, 0x32,
    0xb5, 0x85, 0x2e, 0x5e, 0xc8, 0x45, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
    0x01, 0xf0, 0xb9, 0xf5, 0x05, 0x00, 0x00, 0x00,
    0x00, 0x16, 0x00, 0x14, 0xad, 0xb8, 0x02, 0x23,
    0x3d, 0x84, 0x44, 0xa7, 0x72, 0xbf, 0x6c, 0x36,
    0xa3, 0xff, 0x82, 0xee, 0x69, 0xfb, 0xa7, 0x16,
    0x01, 0x40, 0x08, 0x36, 0xe5, 0xbb, 0x73, 0x3c,
    0xfb, 0x11, 0x03, 0x66, 0x11, 0x55, 0x8e, 0x30,
    0x77, 0x2b, 0x16, 0x99, 0x84, 0x1a, 0xc9, 0x4b,
    0xc4, 0x23, 0x51, 0x69, 0x6d, 0xed, 0xab, 0x5b,
    0x5b, 0x5b, 0xbc, 0xbe, 0x46, 0x83, 0xb5, 0x01,
    0x7a, 0xa6, 0x98, 0xa8, 0x45, 0x93, 0x28, 0x17,
    0x48, 0xd1, 0xf4, 0x1e, 0xa1, 0x90, 0x8d, 0x65,
    0x81, 0x23, 0xf9, 0x70, 0x41, 0x98, 0x13, 0xc5,
    0x20, 0x0e, 0x00, 0x00, 0x00, 0x00,
};


void address(void)
{
    const struct secp256k1_context_struct *ctx = wally_get_secp_context();

    int rc;

    /////////////////////////////////////////////////////////
    // round 0: それぞれからpubkeyを取得
    uint8_t pubkeys[SIGNER_NUM][EC_PUBLIC_KEY_LEN];
    rc = signerGetPubkey(pubkeys[0], 0);
    if (rc) {
        printf("error: signerGetPubkey 0\n");
        return;
    }
    rc = signerGetPubkey(pubkeys[1], 1);
    if (rc) {
        printf("error: signerGetPubkey 1\n");
        return;
    }
    rc = signerGetPubkey(pubkeys[2], 2);
    if (rc) {
        printf("error: signerGetPubkey 2\n");
        return;
    }
    /////////////////////////////////////////////////////////

    const uint8_t *pubkeys_ptr[] = {
        pubkeys[0],
        pubkeys[1],
        pubkeys[2],
    };
    secp256k1_xonly_pubkey agg_pk;
    secp256k1_musig_keyagg_cache cache;
    if (aggPubKey(&agg_pk, &cache, pubkeys_ptr, SIGNER_NUM)) {
        printf("error: aggPubKey fail\n");
        return;
    }

    uint8_t agg_32[EC_XONLY_PUBLIC_KEY_LEN];
    if (!secp256k1_xonly_pubkey_serialize(ctx, agg_32, &agg_pk)) {
        printf("error: secp256k1_xonly_pubkey_serialize fail\n");
        return;
    }
    printf("agg_32: ");
    dump(agg_32, sizeof(agg_32));
    if (memcmp(agg_32, AGG_PUBKEY, sizeof(AGG_PUBKEY)) != 0) {
        printf("agg_32 not same\n");
    }

    uint8_t witnessProgram[WALLY_WITNESSSCRIPT_MAX_LEN];
    size_t witnessProgramLen = 0;
    rc = wally_witness_program_from_bytes_and_version(
             agg_32, sizeof(agg_32),
             1,
             0,
             witnessProgram, sizeof(witnessProgram), &witnessProgramLen);
    if (rc != WALLY_OK) {
        printf("error: wally_witness_program_from_bytes fail: %d\n", rc);
        return;
    }
    printf("witness program: ");
    dump(witnessProgram, witnessProgramLen);

    char *address = NULL;
    rc = wally_addr_segwit_from_bytes(witnessProgram, witnessProgramLen, "bcrt", 0, &address);
    if (rc) {
        printf("error: wally_addr_segwit_from_bytes fail\n");
        goto cleanup;
    }
    printf("address: %s\n", address);
    if (strcmp(address, AGG_ADDR) != 0) {
        printf("address not same\n");
    }

cleanup:
    if (address) {
        wally_free_string(address);
    }
}


void spent(void)
{
    const struct secp256k1_context_struct *ctx = wally_get_secp_context();

    int rc;
    struct wally_tx *tx = NULL;
    struct wally_map *prevScriptPubKey = NULL;
    struct wally_tx_witness_stack *witness = NULL;

    rc = wally_tx_init_alloc(
             2, // version
             0, // locktime
             1, // vin_cnt
             1, // vout_cnt
             &tx);
    if (rc != WALLY_OK) {
        printf("error: wally_tx_init_alloc fail: %d\n", rc);
        goto cleanup;
    }

    const struct wally_tx_input TX_INPUT = {
        .txhash = OUTPOINT_TXHASH,
        .index = OUTPOINT_INDEX,
        .sequence = 0xffffffff,
        .script = NULL,
        .script_len = 0,
        .witness = NULL,
        .features = 0,
    };
    rc = wally_tx_add_input(tx, &TX_INPUT);
    if (rc != WALLY_OK) {
        printf("error: wally_tx_add_input fail: %d\n", rc);
        goto cleanup;
    }

    uint8_t outAddrByte[WALLY_SEGWIT_ADDRESS_PUBKEY_MAX_LEN];
    size_t outAddrLen = 0;
    rc = wally_addr_segwit_to_bytes(
             OUTADDR,
             ADDR_FAMILY,
             0, outAddrByte, sizeof(outAddrByte), &outAddrLen);
    if (rc != WALLY_OK) {
        printf("error: wally_addr_segwit_to_bytes fail: %d\n", rc);
        goto cleanup;
    }

    const struct wally_tx_output TX_OUTPUT = {
        .satoshi = SENT_AMOUNT,
        .script = outAddrByte,
        .script_len = outAddrLen,
        .features = 0,
    };
    rc = wally_tx_add_output(tx, &TX_OUTPUT);
    if (rc != WALLY_OK) {
        printf("error: wally_tx_add_output fail: %d\n", rc);
        goto cleanup;
    }

    rc = wally_map_init_alloc(1, NULL, &prevScriptPubKey);
    if (rc != WALLY_OK) {
        printf("error: wally_map_init_alloc fail: %d\n", rc);
        goto cleanup;
    }
    rc = wally_map_add_integer(
             prevScriptPubKey,
             0, // key
             WITNESS_PROGRAM, sizeof(WITNESS_PROGRAM)); // value
    if (rc != WALLY_OK) {
        printf("error: wally_map_add_integer fail: %d\n", rc);
        goto cleanup;
    }

    uint8_t sigHash[EC_MESSAGE_HASH_LEN];
    const uint64_t VALUES[] = { PREV_AMOUNT };
    rc = wally_tx_get_btc_taproot_signature_hash(
             tx,
             OUTPOINT_INDEX,
             prevScriptPubKey, // scripts
             VALUES, ARRAY_SIZE(VALUES),
             NULL,  0, // tapleaf
             0x00, // key version
             WALLY_NO_CODESEPARATOR, // codesep position
             NULL, 0, // annex
             WALLY_SIGHASH_DEFAULT,
             0, // flags
             sigHash, sizeof(sigHash)
         );
    if (rc != WALLY_OK) {
        printf("error: wally_tx_get_btc_taproot_signature_hash fail: %d\n", rc);
        goto cleanup;
    }
    printf("sigHash: ");
    dump(sigHash, sizeof(sigHash));
    if (memcmp(sigHash, SIGHASH, sizeof(sigHash)) != 0) {
        printf("error: sigHash not same\n");
    }

    /////////////////////////////////////////////////////////
    // round 1: pubnonce取得
    uint8_t pubNonceData[SIGNER_NUM][66];
    rc = signerGetPubNonce(pubNonceData[0], 0, sigHash);
    if (rc != 0) {
        printf("error: signerGetPubNonce 0\n");
        goto cleanup;
    }
    rc = signerGetPubNonce(pubNonceData[1], 1, sigHash);
    if (rc != 0) {
        printf("error: signerGetPubNonce 1\n");
        goto cleanup;
    }
    rc = signerGetPubNonce(pubNonceData[2], 2, sigHash);
    if (rc != 0) {
        printf("error: signerGetPubNonce 2\n");
        goto cleanup;
    }
    /////////////////////////////////////////////////////////

    secp256k1_musig_pubnonce pubnonces[SIGNER_NUM];
    const secp256k1_musig_pubnonce *pubnonce_ptr[SIGNER_NUM];
    for (int i = 0; i < SIGNER_NUM; i++) {
        if (!secp256k1_musig_pubnonce_parse(ctx, &pubnonces[i], pubNonceData[i])) {
            printf("error: secp256k1_musig_pubnonce_parse %d\n", i);
            goto cleanup;
        }
        pubnonce_ptr[i] = &pubnonces[i];
    }

    secp256k1_musig_aggnonce agg_pubnonce;
    if (!secp256k1_musig_nonce_agg(ctx, &agg_pubnonce, pubnonce_ptr, SIGNER_NUM)) {
        printf("error: secp256k1_musig_nonce_agg\n");
        goto cleanup;
    }

    /////////////////////////////////////////////////////////
    // round 2: 部分署名
    /////////////////////////////////////////////////////////
    uint8_t aggNonce[66];
    if (!secp256k1_musig_aggnonce_serialize(ctx, aggNonce, &agg_pubnonce)) {
        printf("error: secp256k1_musig_aggnonce_serialize\n");
        goto cleanup;
    }

    uint8_t partialSigData[SIGNER_NUM][32];
    rc = signerGetPartialSign(partialSigData[0], 0, sigHash, aggNonce, publicKeys, ARRAY_SIZE(publicKeys));
    if (rc != 0) {
        printf("error: signerGetPartialSign 0\n");
        goto cleanup;
    }
    rc = signerGetPartialSign(partialSigData[1], 1, sigHash, aggNonce, publicKeys, ARRAY_SIZE(publicKeys));
    if (rc != 0) {
        printf("error: signerGetPartialSign 1\n");
        goto cleanup;
    }
    rc = signerGetPartialSign(partialSigData[2], 2, sigHash, aggNonce, publicKeys, ARRAY_SIZE(publicKeys));
    if (rc != 0) {
        printf("error: signerGetPartialSign 2\n");
        goto cleanup;
    }
    /////////////////////////////////////////////////////////

    secp256k1_xonly_pubkey agg_pk;
    secp256k1_musig_keyagg_cache cache;
    if (aggPubKey(&agg_pk, &cache, publicKeys, ARRAY_SIZE(publicKeys))) {
        printf("error: aggPubKey fail\n");
        goto cleanup;
    }

    secp256k1_musig_session session;
    if (!secp256k1_musig_nonce_process(ctx, &session, &agg_pubnonce, sigHash, &cache)) {
        printf("error: secp256k1_musig_nonce_process fail\n");
        goto cleanup;
    }

    secp256k1_musig_partial_sig partial_sigs[SIGNER_NUM];
    const secp256k1_musig_partial_sig *partial_sigs_ptr[SIGNER_NUM];
    for (int i = 0; i < SIGNER_NUM; i++) {
        if (!secp256k1_musig_partial_sig_parse(ctx, &partial_sigs[i], partialSigData[i])) {
            printf("error: secp256k1_musig_partial_sig_parse %d\n", i);
            return;
        }

        // verify paritial sign
        secp256k1_pubkey pub;
        if (!secp256k1_ec_pubkey_parse(ctx, &pub, publicKeys[i], EC_PUBLIC_KEY_LEN)) {
            printf("error: secp256k1_ec_pubkey_parse %d\n", i);
            goto cleanup;
        }
        if (!secp256k1_musig_partial_sig_verify(ctx, &partial_sigs[i], &pubnonces[i], &pub, &cache, &session)) {
            printf("error: secp256k1_musig_partial_sig_verify %d\n", i);
            goto cleanup;
        }
        partial_sigs_ptr[i] = &partial_sigs[i];
    }

    uint8_t sig64[64];
    if (!secp256k1_musig_partial_sig_agg(ctx, sig64, &session, partial_sigs_ptr, ARRAY_SIZE(partial_sigs))) {
        printf("error: secp256k1_musig_partial_sig_agg fail\n");
        goto cleanup;
    }
    printf("sig64: ");
    dump(sig64, sizeof(sig64));

    if (memcmp(sig64, SIG, sizeof(sig64)) != 0) {
        printf("error: sig not same\n");
    }

    rc = wally_witness_p2tr_from_sig(sig64, sizeof(sig64), &witness);
    if (rc != WALLY_OK) {
        printf("error: wally_witness_p2tr_from_sig fail: %d\n", rc);
        goto cleanup;
    }
    rc = wally_tx_set_input_witness(tx, 0, witness);
    if (rc != WALLY_OK) {
        printf("error: wally_tx_set_input_witness fail: %d\n", rc);
        goto cleanup;
    }

    uint8_t txData[1024];
    size_t txLen = 0;
    rc = wally_tx_to_bytes(
             tx,
             WALLY_TX_FLAG_USE_WITNESS,
             txData, sizeof(txData), &txLen);
    if (rc != WALLY_OK) {
        printf("error: wally_tx_to_bytes fail: %d\n", rc);
        goto cleanup;
    }
    printf("hex: ");
    dump(txData, txLen);

    if (txLen != sizeof(OUTPUT_RAW_TX)) {
        printf("error: length not match: %lu(expect %lu)\n", txLen, sizeof(OUTPUT_RAW_TX));
    } else if (memcmp(txData, OUTPUT_RAW_TX, txLen) != 0) {
        printf("error: txData not same\n");
    }

cleanup:
    if (prevScriptPubKey) {
        wally_map_free(prevScriptPubKey);
    }
    if (witness) {
        wally_tx_witness_stack_free(witness);
    }
    if (tx) {
        wally_tx_free(tx);
    }
}
