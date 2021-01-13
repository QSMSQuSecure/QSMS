// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include "noise.h"
#include "device.h"
#include "peer.h"
#include "messages.h"
#include "queueing.h"
#include "peerlookup.h"
#include "mceliece/crypto_hash.h"
#include <zinc/chacha20.h>

#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/bitmap.h>
#include <linux/scatterlist.h>
#include <linux/highmem.h>
#include <crypto/algapi.h>
#include <linux/random.h>

/* This implements Noise_IKpsk2:
 *
 * <- s
 * ******
 * -> e, es, s, ss, {t}
 * <- e, ee, se, psk, {}
 */

static const u8 handshake_name[37] = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
static const u8 identifier_name[34] = "WireGuard v1 zx2c4 Jason@zx2c4.com";
static u8 handshake_init_hash[NOISE_HASH_LEN] __ro_after_init;
static u8 handshake_init_chaining_key[NOISE_HASH_LEN] __ro_after_init;
static atomic64_t keypair_counter = ATOMIC64_INIT(0);

// TODO: remove this
static inline void print_sth(u8 *buf, int len, const char* tag) {
        print_hex_dump(KERN_DEBUG, tag, DUMP_PREFIX_NONE, 16, 1, buf, len, false);
}

void __init wg_noise_init(void)
{
	struct blake2s_state blake;

	blake2s(handshake_init_chaining_key, handshake_name, NULL,
		NOISE_HASH_LEN, sizeof(handshake_name), 0);
	blake2s_init(&blake, NOISE_HASH_LEN);
	blake2s_update(&blake, handshake_init_chaining_key, NOISE_HASH_LEN);
	blake2s_update(&blake, identifier_name, sizeof(identifier_name));
	blake2s_final(&blake, handshake_init_hash);
}

static inline void
mix_hash(u8 hash[NOISE_HASH_LEN], const u8 *src, size_t src_len)
{
	struct blake2s_state blake;

	blake2s_init(&blake, NOISE_HASH_LEN);
	blake2s_update(&blake, hash, NOISE_HASH_LEN);
	blake2s_update(&blake, src, src_len);
	blake2s_final(&blake, hash);
}

void wg_noise_handshake_init(struct noise_handshake *handshake,
			   struct noise_static_identity *static_identity,
			   const u8 peer_public_key[NOISE_MC_PUBLIC_KEY_LEN],
			   const u8 peer_preshared_key[NOISE_SYMMETRIC_KEY_LEN],
                           const u8 peer_pk_hash[NOISE_PK_HASH_LEN],
			   struct wg_peer *peer)
{
	memset(handshake, 0, sizeof(*handshake));
	init_rwsem(&handshake->lock);
	handshake->entry.type = INDEX_HASHTABLE_HANDSHAKE;
	handshake->entry.peer = peer;
	memcpy(handshake->remote_mc_pk,peer_public_key,NOISE_MC_PUBLIC_KEY_LEN);
        memcpy(handshake->remote_static_hash, peer_pk_hash, NOISE_PK_HASH_LEN);

        // precompute hash
        memcpy(handshake->precomputed_hash, handshake_init_hash, NOISE_HASH_LEN);
	mix_hash(handshake->precomputed_hash, handshake->remote_mc_pk, NOISE_MC_PUBLIC_KEY_LEN);

	if (peer_preshared_key)
		memcpy(handshake->preshared_key, peer_preshared_key,
		       NOISE_SYMMETRIC_KEY_LEN);
        else { // default PSK is the hash of (spk_i xor spk_r)
            // reuse handshake->remote_mc_pk as a buffer to compute the result of XOR
	    crypto_xor(handshake->remote_mc_pk, static_identity->static_mc_pk,
                    NOISE_MC_PUBLIC_KEY_LEN);
            crypto_hash_32b(handshake->preshared_key, handshake->remote_mc_pk,
                            NOISE_MC_PUBLIC_KEY_LEN);
            // restore the public key
	    memcpy(handshake->remote_mc_pk,peer_public_key, NOISE_MC_PUBLIC_KEY_LEN);
        }
        
	handshake->static_identity = static_identity;
	handshake->state = HANDSHAKE_ZEROED;
}

static void handshake_zero(struct noise_handshake *handshake)
{
	memset(&handshake->hash, 0, NOISE_HASH_LEN);
	memset(&handshake->chaining_key, 0, NOISE_HASH_LEN);

        memset(&handshake->eph_sk, 0, SABER_INDCPA_SECRETKEYBYTES);
        memset(&handshake->eph_pk, 0, SABER_INDCPA_PUBLICKEYBYTES);

        // clear buffers
        memset(&handshake->eph_buf, 0, sizeof(handshake->eph_buf));
        clear_mcbuf(&handshake->mc_buf);

	handshake->remote_index = 0;
	handshake->state = HANDSHAKE_ZEROED;
}

void wg_noise_handshake_clear(struct noise_handshake *handshake)
{
	wg_index_hashtable_remove(
			handshake->entry.peer->device->index_hashtable,
			&handshake->entry);
	down_write(&handshake->lock);
	handshake_zero(handshake);
	up_write(&handshake->lock);
	wg_index_hashtable_remove(
			handshake->entry.peer->device->index_hashtable,
			&handshake->entry);
}

static struct noise_keypair *keypair_create(struct wg_peer *peer)
{
	struct noise_keypair *keypair = kzalloc(sizeof(*keypair), GFP_KERNEL);

	if (unlikely(!keypair))
		return NULL;
	keypair->internal_id = atomic64_inc_return(&keypair_counter);
	keypair->entry.type = INDEX_HASHTABLE_KEYPAIR;
	keypair->entry.peer = peer;
	kref_init(&keypair->refcount);
	return keypair;
}

static void keypair_free_rcu(struct rcu_head *rcu)
{
	kzfree(container_of(rcu, struct noise_keypair, rcu));
}

static void keypair_free_kref(struct kref *kref)
{
	struct noise_keypair *keypair =
		container_of(kref, struct noise_keypair, refcount);

	net_dbg_ratelimited("%s: Keypair %llu destroyed for peer %llu\n",
			    keypair->entry.peer->device->dev->name,
			    keypair->internal_id,
			    keypair->entry.peer->internal_id);
	wg_index_hashtable_remove(keypair->entry.peer->device->index_hashtable,
				  &keypair->entry);
	call_rcu(&keypair->rcu, keypair_free_rcu);
}

void wg_noise_keypair_put(struct noise_keypair *keypair, bool unreference_now)
{
	if (unlikely(!keypair))
		return;
	if (unlikely(unreference_now))
		wg_index_hashtable_remove(
			keypair->entry.peer->device->index_hashtable,
			&keypair->entry);
	kref_put(&keypair->refcount, keypair_free_kref);
}

struct noise_keypair *wg_noise_keypair_get(struct noise_keypair *keypair)
{
	RCU_LOCKDEP_WARN(!rcu_read_lock_bh_held(),
		"Taking noise keypair reference without holding the RCU BH read lock");
	if (unlikely(!keypair || !kref_get_unless_zero(&keypair->refcount)))
		return NULL;
	return keypair;
}

void wg_noise_keypairs_clear(struct noise_keypairs *keypairs)
{
	struct noise_keypair *old;

	spin_lock_bh(&keypairs->keypair_update_lock);

	/* We zero the next_keypair before zeroing the others, so that
	 * wg_noise_received_with_keypair returns early before subsequent ones
	 * are zeroed.
	 */
	old = rcu_dereference_protected(keypairs->next_keypair,
		lockdep_is_held(&keypairs->keypair_update_lock));
	RCU_INIT_POINTER(keypairs->next_keypair, NULL);
	wg_noise_keypair_put(old, true);

	old = rcu_dereference_protected(keypairs->previous_keypair,
		lockdep_is_held(&keypairs->keypair_update_lock));
	RCU_INIT_POINTER(keypairs->previous_keypair, NULL);
	wg_noise_keypair_put(old, true);

	old = rcu_dereference_protected(keypairs->current_keypair,
		lockdep_is_held(&keypairs->keypair_update_lock));
	RCU_INIT_POINTER(keypairs->current_keypair, NULL);
	wg_noise_keypair_put(old, true);

	spin_unlock_bh(&keypairs->keypair_update_lock);
}

void wg_noise_expire_current_peer_keypairs(struct wg_peer *peer)
{
	struct noise_keypair *keypair;

	wg_noise_handshake_clear(&peer->handshake);
	wg_noise_reset_last_sent_handshake(&peer->last_sent_handshake);

	spin_lock_bh(&peer->keypairs.keypair_update_lock);
	keypair = rcu_dereference_protected(peer->keypairs.next_keypair,
			lockdep_is_held(&peer->keypairs.keypair_update_lock));
	if (keypair)
		keypair->sending.is_valid = false;
	keypair = rcu_dereference_protected(peer->keypairs.current_keypair,
			lockdep_is_held(&peer->keypairs.keypair_update_lock));
	if (keypair)
		keypair->sending.is_valid = false;
	spin_unlock_bh(&peer->keypairs.keypair_update_lock);
}

static void add_new_keypair(struct noise_keypairs *keypairs,
			    struct noise_keypair *new_keypair)
{
	struct noise_keypair *previous_keypair, *next_keypair, *current_keypair;

	spin_lock_bh(&keypairs->keypair_update_lock);
	previous_keypair = rcu_dereference_protected(keypairs->previous_keypair,
		lockdep_is_held(&keypairs->keypair_update_lock));
	next_keypair = rcu_dereference_protected(keypairs->next_keypair,
		lockdep_is_held(&keypairs->keypair_update_lock));
	current_keypair = rcu_dereference_protected(keypairs->current_keypair,
		lockdep_is_held(&keypairs->keypair_update_lock));
	if (new_keypair->i_am_the_initiator) {
		/* If we're the initiator, it means we've sent a handshake, and
		 * received a confirmation response, which means this new
		 * keypair can now be used.
		 */
		if (next_keypair) {
			/* If there already was a next keypair pending, we
			 * demote it to be the previous keypair, and free the
			 * existing current. Note that this means KCI can result
			 * in this transition. It would perhaps be more sound to
			 * always just get rid of the unused next keypair
			 * instead of putting it in the previous slot, but this
			 * might be a bit less robust. Something to think about
			 * for the future.
			 */
			RCU_INIT_POINTER(keypairs->next_keypair, NULL);
			rcu_assign_pointer(keypairs->previous_keypair,
					   next_keypair);
			wg_noise_keypair_put(current_keypair, true);
		} else /* If there wasn't an existing next keypair, we replace
			* the previous with the current one.
			*/
			rcu_assign_pointer(keypairs->previous_keypair,
					   current_keypair);
		/* At this point we can get rid of the old previous keypair, and
		 * set up the new keypair.
		 */
		wg_noise_keypair_put(previous_keypair, true);
		rcu_assign_pointer(keypairs->current_keypair, new_keypair);
	} else {
		/* If we're the responder, it means we can't use the new keypair
		 * until we receive confirmation via the first data packet, so
		 * we get rid of the existing previous one, the possibly
		 * existing next one, and slide in the new next one.
		 */
		rcu_assign_pointer(keypairs->next_keypair, new_keypair);
		wg_noise_keypair_put(next_keypair, true);
		RCU_INIT_POINTER(keypairs->previous_keypair, NULL);
		wg_noise_keypair_put(previous_keypair, true);
	}
	spin_unlock_bh(&keypairs->keypair_update_lock);
}

bool wg_noise_received_with_keypair(struct noise_keypairs *keypairs,
				    struct noise_keypair *received_keypair)
{
	struct noise_keypair *old_keypair;
	bool key_is_new;

	/* We first check without taking the spinlock. */
	key_is_new = received_keypair ==
		     rcu_access_pointer(keypairs->next_keypair);
	if (likely(!key_is_new))
		return false;

	spin_lock_bh(&keypairs->keypair_update_lock);
	/* After locking, we double check that things didn't change from
	 * beneath us.
	 */
	if (unlikely(received_keypair !=
		    rcu_dereference_protected(keypairs->next_keypair,
			    lockdep_is_held(&keypairs->keypair_update_lock)))) {
		spin_unlock_bh(&keypairs->keypair_update_lock);
		return false;
	}

	/* When we've finally received the confirmation, we slide the next
	 * into the current, the current into the previous, and get rid of
	 * the old previous.
	 */
	old_keypair = rcu_dereference_protected(keypairs->previous_keypair,
		lockdep_is_held(&keypairs->keypair_update_lock));
	rcu_assign_pointer(keypairs->previous_keypair,
		rcu_dereference_protected(keypairs->current_keypair,
			lockdep_is_held(&keypairs->keypair_update_lock)));
	wg_noise_keypair_put(old_keypair, true);
	rcu_assign_pointer(keypairs->current_keypair, received_keypair);
	RCU_INIT_POINTER(keypairs->next_keypair, NULL);

	spin_unlock_bh(&keypairs->keypair_update_lock);
	return true;
}

/* Must hold static identity->lock */
void wg_noise_set_static_mc_keypair(struct noise_static_identity *static_identity,
                                    const u8 mc_sk[NOISE_MC_SECRET_KEY_LEN],
                                    const u8 mc_pk[NOISE_MC_PUBLIC_KEY_LEN],
                                    const u8 pk_hash[NOISE_PK_HASH_LEN])
{
        memcpy(static_identity->static_mc_sk, mc_sk, NOISE_MC_SECRET_KEY_LEN);
        memcpy(static_identity->static_mc_pk, mc_pk, NOISE_MC_PUBLIC_KEY_LEN);
        memcpy(static_identity->static_hash, pk_hash, NOISE_PK_HASH_LEN);
        static_identity->has_mc_identity = true;

        // by default use two random secrets from the (untrusted) RNG
        // for the twisted PRF trick
        get_random_bytes(static_identity->tprf_k1, NOISE_TWISTED_PRF_KEY_LEN);
        get_random_bytes(static_identity->tprf_k2, NOISE_TWISTED_PRF_KEY_LEN);

        // precompute hash
        memcpy(static_identity->precomputed_hash, handshake_init_hash, NOISE_HASH_LEN);
	mix_hash(static_identity->precomputed_hash, static_identity->static_mc_pk, NOISE_MC_PUBLIC_KEY_LEN);
}

/* Must hold static identity->lock */
void wg_noise_set_tprf_k1(struct noise_static_identity *static_identity,
                            const u8 k1[NOISE_TWISTED_PRF_KEY_LEN]) {
        memcpy(static_identity->tprf_k1, k1, NOISE_TWISTED_PRF_KEY_LEN);
}
void wg_noise_set_tprf_k2(struct noise_static_identity *static_identity,
                            const u8 k2[NOISE_TWISTED_PRF_KEY_LEN]) {
        memcpy(static_identity->tprf_k2, k2, NOISE_TWISTED_PRF_KEY_LEN);
}

/* This is Hugo Krawczyk's HKDF:
 *  - https://eprint.iacr.org/2010/264.pdf
 *  - https://tools.ietf.org/html/rfc5869
 */
static void kdf(u8 *first_dst, u8 *second_dst, u8 *third_dst, const u8 *data,
		size_t first_len, size_t second_len, size_t third_len,
		size_t data_len, const u8 chaining_key[NOISE_HASH_LEN])
{
	u8 output[BLAKE2S_HASH_SIZE + 1];
	u8 secret[BLAKE2S_HASH_SIZE];

	WARN_ON(IS_ENABLED(DEBUG) &&
		(first_len > BLAKE2S_HASH_SIZE ||
		 second_len > BLAKE2S_HASH_SIZE ||
		 third_len > BLAKE2S_HASH_SIZE ||
		 ((second_len || second_dst || third_len || third_dst) &&
		  (!first_len || !first_dst)) ||
		 ((third_len || third_dst) && (!second_len || !second_dst))));

	/* Extract entropy from data into secret */
	blake2s_hmac(secret, data, chaining_key, BLAKE2S_HASH_SIZE, data_len,
		     NOISE_HASH_LEN);

	if (!first_dst || !first_len)
		goto out;

	/* Expand first key: key = secret, data = 0x1 */
	output[0] = 1;
	blake2s_hmac(output, output, secret, BLAKE2S_HASH_SIZE, 1,
		     BLAKE2S_HASH_SIZE);
	memcpy(first_dst, output, first_len);

	if (!second_dst || !second_len)
		goto out;

	/* Expand second key: key = secret, data = first-key || 0x2 */
	output[BLAKE2S_HASH_SIZE] = 2;
	blake2s_hmac(output, output, secret, BLAKE2S_HASH_SIZE,
		     BLAKE2S_HASH_SIZE + 1, BLAKE2S_HASH_SIZE);
	memcpy(second_dst, output, second_len);

	if (!third_dst || !third_len)
		goto out;

	/* Expand third key: key = secret, data = second-key || 0x3 */
	output[BLAKE2S_HASH_SIZE] = 3;
	blake2s_hmac(output, output, secret, BLAKE2S_HASH_SIZE,
		     BLAKE2S_HASH_SIZE + 1, BLAKE2S_HASH_SIZE);
	memcpy(third_dst, output, third_len);

out:
	/* Clear sensitive data from stack */
	memzero_explicit(secret, BLAKE2S_HASH_SIZE);
	memzero_explicit(output, BLAKE2S_HASH_SIZE + 1);
}

static void symmetric_key_init(struct noise_symmetric_key *key)
{
	spin_lock_init(&key->counter.receive.lock);
	atomic64_set(&key->counter.counter, 0);
	memset(key->counter.receive.backtrack, 0,
	       sizeof(key->counter.receive.backtrack));
	key->birthdate = ktime_get_coarse_boottime_ns();
	key->is_valid = true;
        key->ts_updated = false;
}

static void derive_keys(struct noise_symmetric_key *first_dst,
			struct noise_symmetric_key *second_dst,
			const u8 chaining_key[NOISE_HASH_LEN],
                        const u8 ts[NOISE_TIMESTAMP_LEN])
{
	kdf(first_dst->key, second_dst->key, NULL, NULL,
	    NOISE_SYMMETRIC_KEY_LEN, NOISE_SYMMETRIC_KEY_LEN, 0, 0,
	    chaining_key);
	symmetric_key_init(first_dst);
	symmetric_key_init(second_dst);
        memcpy(first_dst->handshake_ts, ts, NOISE_TIMESTAMP_LEN);
        memcpy(second_dst->handshake_ts, ts, NOISE_TIMESTAMP_LEN);
}

static inline void
mix_s(u8 out[NOISE_HASH_LEN], const u8 key[NOISE_SYMMETRIC_KEY_LEN],
      const u8 chaining_key[NOISE_HASH_LEN])
{
        kdf(out, NULL, NULL, key, NOISE_HASH_LEN, 0, 0,
            NOISE_SYMMETRIC_KEY_LEN, chaining_key);
}

static inline void
mix_s_gen(u8 out[NOISE_HASH_LEN], u8 key[NOISE_SYMMETRIC_KEY_LEN],
    const u8 s[NOISE_SYMMETRIC_KEY_LEN], const u8 chaining_key[NOISE_HASH_LEN])
{
        kdf(out, key, NULL, s, NOISE_HASH_LEN, NOISE_SYMMETRIC_KEY_LEN, 0,
            NOISE_SYMMETRIC_KEY_LEN, chaining_key);
}

static void inline
mix_psk(u8 chaining_key[NOISE_HASH_LEN], u8 hash[NOISE_HASH_LEN],
        u8 key[NOISE_SYMMETRIC_KEY_LEN], const u8 psk[NOISE_SYMMETRIC_KEY_LEN])
{
	u8 temp_hash[NOISE_HASH_LEN];

	kdf(chaining_key, temp_hash, key, psk, NOISE_HASH_LEN, NOISE_HASH_LEN,
	    NOISE_SYMMETRIC_KEY_LEN, NOISE_SYMMETRIC_KEY_LEN, chaining_key);
	mix_hash(hash, temp_hash, NOISE_HASH_LEN);
	memzero_explicit(temp_hash, NOISE_HASH_LEN);
}

static inline void
handshake_init(u8 chaining_key[NOISE_HASH_LEN], u8 hash[NOISE_HASH_LEN],
               const u8 remote_static[NOISE_MC_PUBLIC_KEY_LEN])
{
	memcpy(hash, handshake_init_hash, NOISE_HASH_LEN);
	memcpy(chaining_key, handshake_init_chaining_key, NOISE_HASH_LEN);
	mix_hash(hash, remote_static, NOISE_MC_PUBLIC_KEY_LEN);
}

static inline void
chacha20_xor(u8 *dst, const u8 *src, size_t src_len,
             const u8 key[NOISE_SYMMETRIC_KEY_LEN])
{
        struct chacha20_ctx chacha20_state;
        simd_context_t simd_context;
        chacha20_init(&chacha20_state, key, get_random_u64());
        simd_get(&simd_context);
        chacha20(&chacha20_state, dst, src, src_len, &simd_context);
	simd_put(&simd_context);
}

static inline void
message_encrypt(u8 *dst_ciphertext, const u8 *src_plaintext, size_t src_len,
                u8 key[NOISE_SYMMETRIC_KEY_LEN], u8 hash[NOISE_HASH_LEN])
{
	chacha20poly1305_encrypt(dst_ciphertext, src_plaintext, src_len, hash,
				 NOISE_HASH_LEN,
				 0 /* Always zero for Noise_IK */, key);
	mix_hash(hash, dst_ciphertext, noise_encrypted_len(src_len));
}

static inline bool 
message_decrypt(u8 *dst_plaintext, const u8 *src_ciphertext, size_t src_len,
                u8 key[NOISE_SYMMETRIC_KEY_LEN], u8 hash[NOISE_HASH_LEN])
{
	if (!chacha20poly1305_decrypt(dst_plaintext, src_ciphertext, src_len,
				      hash, NOISE_HASH_LEN,
				      0 /* Always zero for Noise_IK */, key))
		return false;
	mix_hash(hash, src_ciphertext, src_len);
	return true;
}

static inline void
message_ephemeral(const u8 ephemeral_src[NOISE_EPHEMERAL_PUBLIC_KEY_LEN],
                  u8 chaining_key[NOISE_HASH_LEN], u8 hash[NOISE_HASH_LEN])
{
	mix_hash(hash, ephemeral_src, NOISE_EPHEMERAL_PUBLIC_KEY_LEN);
	kdf(chaining_key, NULL, NULL, ephemeral_src, NOISE_HASH_LEN, 0, 0,
	    NOISE_EPHEMERAL_PUBLIC_KEY_LEN, chaining_key);
}

static inline void tai64n_now(u8 output[NOISE_TIMESTAMP_LEN])
{
	struct timespec64 now;

	ktime_get_real_ts64(&now);

	/* In order to prevent some sort of infoleak from precise timers, we
	 * round down the nanoseconds part to the closest rounded-down power of
	 * two to the maximum initiations per second allowed anyway by the
	 * implementation.
	 */
	now.tv_nsec = ALIGN_DOWN(now.tv_nsec,
		rounddown_pow_of_two(NSEC_PER_SEC / INITIATIONS_PER_SECOND));

	/* https://cr.yp.to/libtai/tai64.html */
	*(__be64 *)output = cpu_to_be64(0x400000000000000aULL + now.tv_sec);
	*(__be32 *)(output + sizeof(__be64)) = cpu_to_be32(now.tv_nsec);
}

/* use twisted PRF trick to generate random values */
static void
twisted_prf_gen(u8* const __restrict__ out, u8* const __restrict__ tmp,
                const uint64_t out_len,
                const u8 key1[NOISE_TWISTED_PRF_KEY_LEN],
                const u8 key2[NOISE_TWISTED_PRF_KEY_LEN]) {
    // sample one random value from the untrusted RNG
    u8 rnd_seed[32];
    get_random_bytes(rnd_seed, 32);

    // NOTE: NOISE_TWISTED_PRF_KEY_LEN is the same as NOISE_HASH_LEN
    // so we simply reuse kdf here. Also note that this KDF implemented
    // by WireGuard can only produce keys shorter than BLAKE2S_HASH_SIZE,
    // which is 32 bytes.
    kdf(out, NULL, NULL, rnd_seed, NOISE_HASH_LEN, 0, 0, 32, key1);
}

bool
wg_noise_handshake_create_initiation(struct message_handshake_initiation *dst,
				     struct noise_handshake *handshake)
{
	u8 timestamp[NOISE_TIMESTAMP_LEN];
	u8 key[NOISE_SYMMETRIC_KEY_LEN];
        u8 coin[NOISE_EPHEMERAL_COIN_LEN];
        u8 seed[NOISE_EPHEMERAL_SEED_LEN];
	bool ret = false;

	/* We need to wait for crng _before_ taking any locks, since
	 * crypto API uses get_random_bytes_wait.
	 */
	wait_for_random_bytes();

	down_read(&handshake->static_identity->lock);
	down_write(&handshake->lock);

	if (unlikely(!handshake->static_identity->has_mc_identity))
		goto out;

	dst->header.type = cpu_to_le32(MESSAGE_HANDSHAKE_INITIATION);

        // copy precomputed chaining_key and hash
	memcpy(handshake->chaining_key, handshake_init_chaining_key,
                NOISE_HASH_LEN);
	memcpy(handshake->hash, handshake->precomputed_hash, NOISE_HASH_LEN);
        
        // use twisted PRF trick to generate the random seed for ephemeral key
        // use key as the temporary buffer (same length)
        twisted_prf_gen(seed, key, NOISE_EPHEMERAL_SEED_LEN,
                        handshake->static_identity->tprf_k1,
                        handshake->static_identity->tprf_k2);
        
        // use key as the temporary buffer (same length)
        twisted_prf_gen(coin, key, NOISE_EPHEMERAL_COIN_LEN,
                        handshake->static_identity->tprf_k1,
                        handshake->static_identity->tprf_k2);
        
        // create ephemeral key pair
        indcpa_kem_keypair(dst->ephemeral_public, handshake->eph_sk, seed,
                           coin, &handshake->eph_buf);
	// mix ephemeral pk into chaining key and hash
	message_ephemeral(dst->ephemeral_public, handshake->chaining_key,
                          handshake->hash);

        // encapsulate a fresh secret with static McEliece pk of the peer
	if (crypto_kem_mceliece_enc(dst->mc_ciphertext, key,
                                    handshake->remote_mc_pk,
                                    handshake->static_identity->tprf_k1,
                                    handshake->static_identity->tprf_k2)) {
                goto out;
	}

        // mix the fresh secret into chaining key, and generate key k1
        mix_s_gen(handshake->chaining_key, key, key, handshake->chaining_key);

        // encrypt the hash of our own static McEliece pk with k1, and mix
        // the ciphertext into hash
        message_encrypt(dst->encrypted_static,
                        handshake->static_identity->static_hash,
                        NOISE_PK_HASH_LEN, key, handshake->hash);

        // mix PSK into chaining key and generate key k2
        mix_s_gen(handshake->chaining_key, key, handshake->preshared_key,
                  handshake->chaining_key);

        // encrypt the timestamp with k2, and mix the ciphertext into hash
	tai64n_now(timestamp);
	message_encrypt(dst->encrypted_timestamp, timestamp,
                        NOISE_TIMESTAMP_LEN, key, handshake->hash);
        
	dst->sender_index = wg_index_hashtable_insert(
		handshake->entry.peer->device->index_hashtable,
		&handshake->entry);

	handshake->state = HANDSHAKE_CREATED_INITIATION;
	ret = true;

out:
	up_write(&handshake->lock);
	up_read(&handshake->static_identity->lock);
	memzero_explicit(key, NOISE_SYMMETRIC_KEY_LEN);
	memzero_explicit(coin, NOISE_EPHEMERAL_COIN_LEN);
	memzero_explicit(seed, NOISE_EPHEMERAL_SEED_LEN);
	return ret;
}

struct wg_peer *
wg_noise_handshake_consume_initiation(struct message_handshake_initiation *src,
				      struct wg_device *wg)
{
	struct wg_peer *peer = NULL, *ret_peer = NULL;
	struct noise_handshake *handshake;
	bool replay_attack, flood_attack;
	u8 key[NOISE_SYMMETRIC_KEY_LEN];
	u8 chaining_key[NOISE_HASH_LEN];
	u8 hash[NOISE_HASH_LEN];
	u8 static_hash[NOISE_PK_HASH_LEN];
	u8 t[NOISE_TIMESTAMP_LEN];
	u64 initiation_consumption;

	down_read(&wg->static_identity.lock);
	if (unlikely(!wg->static_identity.has_mc_identity))
		goto out;

        // copy precomputed chaining_key and hash
	memcpy(chaining_key, handshake_init_chaining_key, NOISE_HASH_LEN);
	memcpy(hash, wg->static_identity.precomputed_hash, NOISE_HASH_LEN);

	// mix ephemeral pk into chaining key and hash
	message_ephemeral(src->ephemeral_public, chaining_key, hash);
        
        // We need a buffer for McEliece decryption, so pick the 1st peer
        // whose write lock is free
	peer = wg_pubkey_hashtable_random_free(wg->peer_hashtable);
        if (!peer)
                goto out;
        
        // NOTE: write lock's been acquired, no need to call down_write() again
        // decapsulate the secret in McEliece ciphertext
        if (crypto_kem_mceliece_dec(key, src->mc_ciphertext,
                                    wg->static_identity.static_mc_sk,
                                    &peer->handshake.mc_buf)) {
                up_write(&peer->handshake.lock);
                goto out;
        }
        up_write(&peer->handshake.lock); // release write lock of the random peer
        peer = NULL;

        // mix the McEliece fresh secret into chaining key and generate key k1
        mix_s_gen(chaining_key, key, key, chaining_key);

	// decrypt the hash of peer's static McEliece pk with k1, and mix
        // the ciphertext into hash
	if(!message_decrypt(static_hash, src->encrypted_static,
	                    sizeof(src->encrypted_static), key, hash)) {
		goto out;
        }

	/* Lookup which peer we're actually talking to */
	peer = wg_pubkey_hashtable_lookup(wg->peer_hashtable, static_hash);
	if (!peer)
		goto out;
	handshake = &peer->handshake;
	down_read(&handshake->lock);

        // mix PSK into chaining key and generate key k2
        mix_s_gen(chaining_key, key, handshake->preshared_key, chaining_key);

        // TODO: check the format of timestamp?
	// decrypt the timestamp with k2, and mix the ciphertext into hash
	if (!message_decrypt(t, src->encrypted_timestamp,
                             sizeof(src->encrypted_timestamp), key, hash)) {
                up_read(&handshake->lock);
		goto out;
        }

        // TODO: perhaps there's a better way to check timestamp?
	replay_attack = memcmp(t, handshake->latest_timestamp,
			       NOISE_TIMESTAMP_LEN) <= 0;
	flood_attack = (s64)handshake->last_initiation_consumption +
			       NSEC_PER_SEC / INITIATIONS_PER_SECOND >
		       (s64)ktime_get_coarse_boottime_ns();

	if (replay_attack || flood_attack) {
	        up_read(&handshake->lock);
		goto out;
        }

	up_read(&handshake->lock);

	/* Success! Copy everything to peer */
	down_write(&handshake->lock);
	memcpy(handshake->eph_pk, src->ephemeral_public,
               NOISE_EPHEMERAL_PUBLIC_KEY_LEN);
        // NOTE: we do not update timestamp until key confirmation
        if (memcmp(t, handshake->unconfirmed_ts, NOISE_TIMESTAMP_LEN) > 0)
	    memcpy(handshake->unconfirmed_ts, t, NOISE_TIMESTAMP_LEN);
	memcpy(handshake->hash, hash, NOISE_HASH_LEN);
	memcpy(handshake->chaining_key, chaining_key, NOISE_HASH_LEN);

	handshake->remote_index = src->sender_index;
	if ((s64)(handshake->last_initiation_consumption -
	    (initiation_consumption = ktime_get_coarse_boottime_ns())) < 0)
		handshake->last_initiation_consumption = initiation_consumption;
	handshake->state = HANDSHAKE_CONSUMED_INITIATION;
	up_write(&handshake->lock);
	ret_peer = peer;

out:
	memzero_explicit(key, NOISE_SYMMETRIC_KEY_LEN);
	memzero_explicit(hash, NOISE_HASH_LEN);
	memzero_explicit(chaining_key, NOISE_HASH_LEN);

	up_read(&wg->static_identity.lock);
	if (!ret_peer)
		wg_peer_put(peer);
	return ret_peer;
}

bool wg_noise_handshake_create_response(struct message_handshake_response *dst,
					struct noise_handshake *handshake)
{
	u8 key[NOISE_SYMMETRIC_KEY_LEN];
        u8 coin[NOISE_SYMMETRIC_KEY_LEN + NOISE_EPHEMERAL_COIN_LEN];
        u8 buf[NOISE_EPHEMERAL_COIN_LEN]; // same as NOISE_SYMMETRIC_KEY_LEN
        u8 encrypted_nothing[noise_encrypted_len(0)];
	bool ret = false;

	/* We need to wait for crng _before_ taking any locks, since
	 * crypto API uses get_random_bytes_wait.
	 */
	wait_for_random_bytes();

	down_read(&handshake->static_identity->lock);
	down_write(&handshake->lock);

	if (handshake->state != HANDSHAKE_CONSUMED_INITIATION)
		goto out;

	dst->header.type = cpu_to_le32(MESSAGE_HANDSHAKE_RESPONSE);
	dst->receiver_index = handshake->remote_index;

        // use the twisted PRF trick to encapsulate a fresh secret with static
        // McEliece pk of the peer
        if (crypto_kem_mceliece_enc(dst->mc_ciphertext, key,
                                    handshake->remote_mc_pk,
                                    handshake->static_identity->tprf_k1,
                                    handshake->static_identity->tprf_k2)) {
                goto out;
        }

        // mix McEliece ciphertext into chaining_key
        mix_hash(handshake->chaining_key, dst->mc_ciphertext,
                 NOISE_MC_CIPHERTEXT_LEN);

        // mix McEliece ciphertext into hash
        mix_hash(handshake->hash, dst->mc_ciphertext, NOISE_MC_CIPHERTEXT_LEN);

        // mix the McEliece fresh secret into chaining key
        mix_s(handshake->chaining_key, key, handshake->chaining_key);

        // use twisted PRF trick to generate the noiseseed
        twisted_prf_gen(coin, buf, NOISE_EPHEMERAL_COIN_LEN,
                        handshake->static_identity->tprf_k1,
                        handshake->static_identity->tprf_k2);

        // the generated secret will be fill into key
        saber_indcpa_enc(dst->ephemeral_ciphertext, key, handshake->eph_pk, coin,
                         &handshake->eph_buf);

        // mix the fresh secret into chaining key
        mix_s(handshake->chaining_key, key, handshake->chaining_key);

	// mix psk into chaining key, generate two secrets tau and kappa, and
        // mix tau into hash. key is overwritten with kappa.
	mix_psk(handshake->chaining_key, handshake->hash, key,
		handshake->preshared_key);

	// encrypt empty string with AEAD keyed by kappa, and use hash as AD
	message_encrypt(dst->encrypted_nothing, NULL, 0, key, handshake->hash);

	dst->sender_index = wg_index_hashtable_insert(
		handshake->entry.peer->device->index_hashtable,
		&handshake->entry);

	handshake->state = HANDSHAKE_CREATED_RESPONSE;
	ret = true;

out:
	up_write(&handshake->lock);
	up_read(&handshake->static_identity->lock);
	memzero_explicit(key, NOISE_SYMMETRIC_KEY_LEN);
	memzero_explicit(coin, NOISE_SYMMETRIC_KEY_LEN + NOISE_EPHEMERAL_COIN_LEN);
	memzero_explicit(buf, NOISE_EPHEMERAL_COIN_LEN);
	return ret;
}

struct wg_peer *
wg_noise_handshake_consume_response(struct message_handshake_response *src,
				    struct wg_device *wg)
{
	enum noise_handshake_state state = HANDSHAKE_ZEROED;
	struct wg_peer *peer = NULL, *ret_peer = NULL;
	struct noise_handshake *handshake;
	u8 key[NOISE_SYMMETRIC_KEY_LEN];
	u8 hash[NOISE_HASH_LEN];
	u8 chaining_key[NOISE_HASH_LEN];
        u8 encrypted_nothing[noise_encrypted_len(0)];

	down_read(&wg->static_identity.lock);

	if (unlikely(!wg->static_identity.has_mc_identity))
		goto out;

	handshake = (struct noise_handshake *)wg_index_hashtable_lookup(
		wg->index_hashtable, INDEX_HASHTABLE_HANDSHAKE,
		src->receiver_index, &peer);
	if (unlikely(!handshake))
		goto out;

        // claim write lock coz we need to use the buffer in struct handshake
	down_write(&handshake->lock);
	state = handshake->state;
	memcpy(hash, handshake->hash, NOISE_HASH_LEN);
	memcpy(chaining_key, handshake->chaining_key, NOISE_HASH_LEN);

	if (state != HANDSHAKE_CREATED_INITIATION) {
                up_write(&handshake->lock);
		goto fail;
        }

        // decapsulate the secret in McEliece ciphertext
        if (crypto_kem_mceliece_dec(key, src->mc_ciphertext,
                                    handshake->static_identity->static_mc_sk,
                                    &peer->handshake.mc_buf)) {
                up_write(&handshake->lock);
                goto fail;
        }

        // mix McEliece ciphertext into chaining_key
        mix_hash(chaining_key, src->mc_ciphertext, NOISE_MC_CIPHERTEXT_LEN);

        // mix McEliece ciphertext into hash
        mix_hash(hash, src->mc_ciphertext, NOISE_MC_CIPHERTEXT_LEN);

        // mix the McEliece fresh secret into chaining key
        mix_s(chaining_key, key, chaining_key);

        // decapsulate the secret in ephemeral ciphertext
        saber_indcpa_dec(key, src->ephemeral_ciphertext, handshake->eph_sk,
                         &peer->handshake.eph_buf);
        
        // mix the 2nd fresh secret into chaining key
        mix_s(chaining_key, key, chaining_key);

	// mix psk into chaining key, generate two secrets tau and kappa, and
        // mix tau into hash. key is overwritten with kappa.
	mix_psk(chaining_key, hash, key, handshake->preshared_key);

	// decrypt and verify the AEAD ciphertext
	if (!message_decrypt(NULL, src->encrypted_nothing,
			     sizeof(src->encrypted_nothing), key, hash)) {
                up_write(&handshake->lock);
		goto fail;
        }

	/* Success! Copy everything to peer */
	/* It's important to check that the state is still the same, while we
	 * have an exclusive lock.
	 */
	if (handshake->state != state) {
		up_write(&handshake->lock);
		goto fail;
	}
	memcpy(handshake->hash, hash, NOISE_HASH_LEN);
	memcpy(handshake->chaining_key, chaining_key, NOISE_HASH_LEN);
        
	handshake->remote_index = src->sender_index;
	handshake->state = HANDSHAKE_CONSUMED_RESPONSE;
	up_write(&handshake->lock);
	ret_peer = peer;
	goto out;

fail:
	wg_peer_put(peer);
out:
	memzero_explicit(key, NOISE_SYMMETRIC_KEY_LEN);
	memzero_explicit(hash, NOISE_HASH_LEN);
	memzero_explicit(chaining_key, NOISE_HASH_LEN);
	up_read(&wg->static_identity.lock);
	return ret_peer;
}

bool wg_noise_handshake_begin_session(struct noise_handshake *handshake,
				      struct noise_keypairs *keypairs)
{
	struct noise_keypair *new_keypair;
	bool ret = false;

	down_write(&handshake->lock);
	if (handshake->state != HANDSHAKE_CREATED_RESPONSE &&
	    handshake->state != HANDSHAKE_CONSUMED_RESPONSE)
		goto out;

	new_keypair = keypair_create(handshake->entry.peer);
	if (!new_keypair)
		goto out;
	new_keypair->i_am_the_initiator = handshake->state ==
					  HANDSHAKE_CONSUMED_RESPONSE;
	new_keypair->remote_index = handshake->remote_index;

	if (new_keypair->i_am_the_initiator)
		derive_keys(&new_keypair->sending, &new_keypair->receiving,
			    handshake->chaining_key, handshake->unconfirmed_ts);
	else
		derive_keys(&new_keypair->receiving, &new_keypair->sending,
			    handshake->chaining_key, handshake->unconfirmed_ts);

	handshake_zero(handshake);
	rcu_read_lock_bh();
	if (likely(!READ_ONCE(container_of(handshake, struct wg_peer,
					   handshake)->is_dead))) {
		add_new_keypair(keypairs, new_keypair);
		net_dbg_ratelimited("%s: Keypair %llu created for peer %llu\n",
				    handshake->entry.peer->device->dev->name,
				    new_keypair->internal_id,
				    handshake->entry.peer->internal_id);
		ret = wg_index_hashtable_replace(
			handshake->entry.peer->device->index_hashtable,
			&handshake->entry, &new_keypair->entry);
	} else {
		kzfree(new_keypair);
	}
	rcu_read_unlock_bh();

out:
	up_write(&handshake->lock);
	return ret;
}
