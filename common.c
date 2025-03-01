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

void dump(const uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}


/* Tweak the pubkey corresponding to the provided keyagg cache, update the cache
 * and return the tweaked aggregate pk. */
int tweak(const secp256k1_context* ctx, secp256k1_xonly_pubkey *agg_pk, secp256k1_musig_keyagg_cache *cache)
{
    secp256k1_pubkey output_pk;
    /* For BIP 32 tweaking the plain_tweak is set to a hash as defined in BIP
     * 32. */
    unsigned char plain_tweak[32] = "this could be a BIP32 tweak....";
    /* For Taproot tweaking the xonly_tweak is set to the TapTweak hash as
     * defined in BIP 341 */
    unsigned char xonly_tweak[32] = "this could be a Taproot tweak..";


    /* Plain tweaking which, for example, allows deriving multiple child
     * public keys from a single aggregate key using BIP32 */
    if (!secp256k1_musig_pubkey_ec_tweak_add(ctx, NULL, cache, plain_tweak)) {
        return 1;
    }
    /* Note that we did not provide an output_pk argument, because the
     * resulting pk is also saved in the cache and so if one is just interested
     * in signing, the output_pk argument is unnecessary. On the other hand, if
     * one is not interested in signing, the same output_pk can be obtained by
     * calling `secp256k1_musig_pubkey_get` right after key aggregation to get
     * the full pubkey and then call `secp256k1_ec_pubkey_tweak_add`. */

    /* Xonly tweaking which, for example, allows creating Taproot commitments */
    if (!secp256k1_musig_pubkey_xonly_tweak_add(ctx, &output_pk, cache, xonly_tweak)) {
        return 1;
    }
    /* Note that if we wouldn't care about signing, we can arrive at the same
     * output_pk by providing the untweaked public key to
     * `secp256k1_xonly_pubkey_tweak_add` (after converting it to an xonly pubkey
     * if necessary with `secp256k1_xonly_pubkey_from_pubkey`). */

    /* Now we convert the output_pk to an xonly pubkey to allow to later verify
     * the Schnorr signature against it. For this purpose we can ignore the
     * `pk_parity` output argument; we would need it if we would have to open
     * the Taproot commitment. */
    if (!secp256k1_xonly_pubkey_from_pubkey(ctx, agg_pk, NULL, &output_pk)) {
        return 1;
    }
    return 0;
}


// 通信の順番に影響されないようpubkeyデータでソートしてから集約する
int aggPubKey(
    secp256k1_xonly_pubkey *agg_pk,
    secp256k1_musig_keyagg_cache *cache,
    const uint8_t *pubkeys[],
    int keyNum)
{
    const struct secp256k1_context_struct *ctx = wally_get_secp_context();

    secp256k1_pubkey *secp_pubkeys = (secp256k1_pubkey *)malloc(sizeof(secp256k1_pubkey) * keyNum);
    const secp256k1_pubkey **pubkeys_ptr = (const secp256k1_pubkey **)malloc(sizeof(secp256k1_pubkey*) * keyNum);

    for (int i = 0; i < keyNum; i++) {
        if (!secp256k1_ec_pubkey_parse(ctx, &secp_pubkeys[i], pubkeys[i], EC_PUBLIC_KEY_LEN)) {
            printf("error: secp256k1_ec_pubkey_parse %d\n", i);
            return 1;
        }
        pubkeys_ptr[i] = &secp_pubkeys[i];
    }
    if (!secp256k1_ec_pubkey_sort(ctx, pubkeys_ptr, keyNum)) {
        printf("error: secp256k1_ec_pubkey_sort\n");
        return 1;
    }
    if (!secp256k1_musig_pubkey_agg(ctx, NULL, cache, pubkeys_ptr, keyNum)) {
        printf("error: secp256k1_musig_pubkey_agg\n");
        return 1;
    }
    if (tweak(ctx, agg_pk, cache)) {
        printf("error: secp256k1_xonly_pubkey fail\n");
        return 1;
    }

    free(pubkeys_ptr);
    free(secp_pubkeys);
    return 0;
}
