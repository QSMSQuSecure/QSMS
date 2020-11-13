/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */
#ifndef _WG_NOISE_H
#define _WG_NOISE_H

#include "messages.h"
#include "ephemeral/SABER_params.h"
#include "ephemeral/SABER_indcpa.h"
#include "ephemeral/kem.h"
#include "mceliece/params.h"
#include "mceliece/mcbuf.h"
#include "ephemeral/ephemeral_buf.h"
#include "peerlookup.h"

#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/atomic.h>
#include <linux/rwsem.h>
#include <linux/mutex.h>
#include <linux/kref.h>

union noise_counter {
	struct {
		u64 counter;
		unsigned long backtrack[COUNTER_BITS_TOTAL / BITS_PER_LONG];
		spinlock_t lock;
	} receive;
	atomic64_t counter;
};

struct noise_symmetric_key {
	u8 key[NOISE_SYMMETRIC_KEY_LEN];
	u8 handshake_ts[NOISE_TIMESTAMP_LEN];
	union noise_counter counter;
	u64 birthdate;
	bool is_valid;
        bool ts_updated;
};

struct noise_keypair {
	struct index_hashtable_entry entry;
	struct noise_symmetric_key sending;
	struct noise_symmetric_key receiving;
	__le32 remote_index;
	bool i_am_the_initiator;
	struct kref refcount;
	struct rcu_head rcu;
	u64 internal_id;
};

struct noise_keypairs {
	struct noise_keypair __rcu *current_keypair;
	struct noise_keypair __rcu *previous_keypair;
	struct noise_keypair __rcu *next_keypair;
	spinlock_t keypair_update_lock;
};

struct noise_static_identity {
        u8 static_mc_pk[NOISE_MC_PUBLIC_KEY_LEN];
        u8 static_mc_sk[NOISE_MC_SECRET_KEY_LEN];
        u8 static_hash[NOISE_PK_HASH_LEN];
        u8 tprf_k1[NOISE_TWISTED_PRF_KEY_LEN];
        u8 tprf_k2[NOISE_TWISTED_PRF_KEY_LEN];
        u8 precomputed_hash[NOISE_HASH_LEN];
        bool has_mc_identity;
	struct rw_semaphore lock;
};

enum noise_handshake_state {
	HANDSHAKE_ZEROED,
	HANDSHAKE_CREATED_INITIATION,
	HANDSHAKE_CONSUMED_INITIATION,
	HANDSHAKE_CREATED_RESPONSE,
	HANDSHAKE_CONSUMED_RESPONSE
};

struct noise_handshake {
	struct index_hashtable_entry entry;
	enum noise_handshake_state state;
	u64 last_initiation_consumption;
	struct noise_static_identity *static_identity;
        u8 remote_static_hash[NOISE_PK_HASH_LEN];
        u8 remote_mc_pk[NOISE_MC_PUBLIC_KEY_LEN];
        u8 precomputed_hash[NOISE_HASH_LEN];
	u8 eph_pk[SABER_INDCPA_PUBLICKEYBYTES];
	u8 eph_sk[SABER_INDCPA_SECRETKEYBYTES];
	u8 preshared_key[NOISE_SYMMETRIC_KEY_LEN];
	u8 hash[NOISE_HASH_LEN];
	u8 chaining_key[NOISE_HASH_LEN];
	u8 latest_timestamp[NOISE_TIMESTAMP_LEN];
        u8 unconfirmed_ts[NOISE_TIMESTAMP_LEN];
	__le32 remote_index;

	/* Protects all members except the immutable (after noise_handshake_
	 * init): remote_mc_pk, remote_static_hash, static_identity.
	 */
	struct rw_semaphore lock;

        struct mc_buffer mc_buf;
        struct eph_buffer eph_buf;
};

struct wg_device;

void wg_noise_init(void);
void wg_noise_handshake_init(struct noise_handshake *handshake,
			   struct noise_static_identity *static_identity,
			   const u8 peer_public_key[NOISE_MC_PUBLIC_KEY_LEN],
			   const u8 peer_preshared_key[NOISE_SYMMETRIC_KEY_LEN],
                           const u8 peer_pk_hash[NOISE_PK_HASH_LEN],
			   struct wg_peer *peer);
void wg_noise_handshake_clear(struct noise_handshake *handshake);
static inline void wg_noise_reset_last_sent_handshake(atomic64_t *handshake_ns)
{
	atomic64_set(handshake_ns, ktime_get_coarse_boottime_ns() -
				       (u64)(REKEY_TIMEOUT + 1) * NSEC_PER_SEC);
}

void wg_noise_keypair_put(struct noise_keypair *keypair, bool unreference_now);
struct noise_keypair *wg_noise_keypair_get(struct noise_keypair *keypair);
void wg_noise_keypairs_clear(struct noise_keypairs *keypairs);
bool wg_noise_received_with_keypair(struct noise_keypairs *keypairs,
				    struct noise_keypair *received_keypair);

void wg_noise_set_static_mc_keypair(struct noise_static_identity *static_identity,
                                    const u8 mc_sk[NOISE_MC_SECRET_KEY_LEN],
                                    const u8 mc_pk[NOISE_MC_PUBLIC_KEY_LEN],
                                    const u8 pk_hash[NOISE_PK_HASH_LEN]);

void wg_noise_set_tprf_k1(struct noise_static_identity *static_identity,
                          const u8 k1[NOISE_TWISTED_PRF_KEY_LEN]);
void wg_noise_set_tprf_k2(struct noise_static_identity *static_identity,
                          const u8 k2[NOISE_TWISTED_PRF_KEY_LEN]);

void wg_noise_expire_current_peer_keypairs(struct wg_peer *peer);

bool
wg_noise_handshake_create_initiation(struct message_handshake_initiation *dst,
				     struct noise_handshake *handshake);
struct wg_peer *
wg_noise_handshake_consume_initiation(struct message_handshake_initiation *src,
				      struct wg_device *wg);

bool wg_noise_handshake_create_response(struct message_handshake_response *dst,
					struct noise_handshake *handshake);
struct wg_peer *
wg_noise_handshake_consume_response(struct message_handshake_response *src,
				    struct wg_device *wg);

bool wg_noise_handshake_begin_session(struct noise_handshake *handshake,
				      struct noise_keypairs *keypairs);

#endif /* _WG_NOISE_H */
