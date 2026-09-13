use libp2p::{Multiaddr, PeerId};
use redb::ReadableTable;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

const BANNED_REPUTATION_THRESHOLD: i32 = crate::BANNED_REPUTATION_THRESHOLD;
const INVALID_MESSAGE_PENALTY: i32 = 25;
const DUPLICATE_MESSAGE_PENALTY: i32 = 5;
const RATE_LIMIT_PENALTY: i32 = 10;
const MAX_PEERS_PER_SUBNET: usize = crate::MAX_PEERS_PER_SUBNET;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Peer {
    pub peer_id: PeerId,
    pub address: String,
    pub last_seen: u64,
    pub reputation: i32,
}

impl Peer {
    pub fn new(peer_id: PeerId, address: Multiaddr) -> Self {
        Self {
            peer_id,
            address: address.to_string(),
            last_seen: Self::unix_timestamp(),
            reputation: 0,
        }
    }

    pub fn update_last_seen(&mut self) {
        self.last_seen = Self::unix_timestamp();
    }

    pub fn increase_reputation(&mut self, amount: i32) {
        self.reputation = self.reputation.saturating_add(amount.max(0));
    }

    pub fn decrease_reputation(&mut self, amount: i32) {
        self.reputation = self.reputation.saturating_sub(amount.max(0));
    }

    pub fn is_banned(&self) -> bool {
        self.reputation <= BANNED_REPUTATION_THRESHOLD
    }

    fn unix_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BanEntry {
    pub reason: String,
    pub score: i32,
    pub created_at: u64,
    pub expires_at: Option<u64>,
}

#[derive(Clone, Default)]
pub struct PeerStore {
    pub peers: HashMap<PeerId, Peer>,
    pub db: Option<std::sync::Arc<redb::Database>>,
}

// Implement Debug manually because Database doesn't implement Debug
impl std::fmt::Debug for PeerStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerStore")
            .field("peers", &self.peers)
            .field("db", &self.db.is_some())
            .finish()
    }
}

const TABLE_PEER_BANS: redb::TableDefinition<&str, &[u8]> = redb::TableDefinition::new("peer_bans");

impl PeerStore {
    pub fn new(db: Option<std::sync::Arc<redb::Database>>) -> Self {
        let mut store = Self {
            peers: HashMap::new(),
            db,
        };
        store.load_bans_from_db();
        store
    }

    fn load_bans_from_db(&mut self) {
        let mut expired_keys = Vec::new();
        let now = Peer::unix_timestamp();
        if let Some(db) = &self.db {
            if let Ok(txn) = db.begin_read() {
                if let Ok(table) = txn.open_table(TABLE_PEER_BANS) {
                    if let Ok(iter) = table.iter() {
                        for (k_guard, v_guard) in iter.flatten() {
                            let k_str = k_guard.value();
                            if let Ok(peer_id) = k_str.parse::<PeerId>() {
                                if let Ok(entry) = bincode::deserialize::<BanEntry>(v_guard.value())
                                {
                                    if let Some(exp) = entry.expires_at {
                                        if now > exp {
                                            expired_keys.push(k_str.to_string());
                                            continue; // Expired
                                        }
                                    }
                                    // Load peer ban into memory. If peer doesn't exist, create a stub peer to hold the ban.
                                    let peer = self.peers.entry(peer_id).or_insert_with(|| Peer {
                                        peer_id,
                                        address: String::new(),
                                        reputation: BANNED_REPUTATION_THRESHOLD,
                                        last_seen: now,
                                    });
                                    peer.reputation = entry.score.min(BANNED_REPUTATION_THRESHOLD);
                                }
                            }
                        }
                    }
                }
            }

            // Clean up expired bans from redb table
            if !expired_keys.is_empty() {
                if let Ok(txn) = db.begin_write() {
                    if let Ok(mut table) = txn.open_table(TABLE_PEER_BANS) {
                        for k in expired_keys {
                            let _ = table.remove(k.as_str());
                        }
                    }
                    let _ = txn.commit();
                }
            }
        }
    }

    pub fn prune_expired_bans(&mut self) {
        let now = Peer::unix_timestamp();
        let mut unbanned_peers = Vec::new();
        let mut expired_keys = Vec::new();

        if let Some(db) = &self.db {
            if let Ok(txn) = db.begin_read() {
                if let Ok(table) = txn.open_table(TABLE_PEER_BANS) {
                    if let Ok(iter) = table.iter() {
                        for (k_guard, v_guard) in iter.flatten() {
                            let k_str = k_guard.value();
                            if let Ok(entry) = bincode::deserialize::<BanEntry>(v_guard.value()) {
                                if let Some(exp) = entry.expires_at {
                                    if now > exp {
                                        expired_keys.push(k_str.to_string());
                                        if let Ok(peer_id) = k_str.parse::<PeerId>() {
                                            unbanned_peers.push(peer_id);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if !expired_keys.is_empty() {
                if let Ok(txn) = db.begin_write() {
                    if let Ok(mut table) = txn.open_table(TABLE_PEER_BANS) {
                        for k in expired_keys {
                            let _ = table.remove(k.as_str());
                        }
                    }
                    let _ = txn.commit();
                }
            }
        }

        for peer_id in unbanned_peers {
            if let Some(peer) = self.peers.get_mut(&peer_id) {
                if peer.is_banned() {
                    peer.reputation = 0;
                }
            }
        }
    }

    fn save_ban_to_db(&self, peer_id: &PeerId, entry: &BanEntry) {
        if let Some(db) = &self.db {
            if let Ok(txn) = db.begin_write() {
                if let Ok(mut table) = txn.open_table(TABLE_PEER_BANS) {
                    if let Ok(bytes) = bincode::serialize(entry) {
                        let id_str = peer_id.to_string();
                        let _ = table.insert(id_str.as_str(), bytes.as_slice());
                    }
                }
                let _ = txn.commit();
            }
        }
    }

    fn remove_ban_from_db(&self, peer_id: &PeerId) {
        if let Some(db) = &self.db {
            if let Ok(txn) = db.begin_write() {
                if let Ok(mut table) = txn.open_table(TABLE_PEER_BANS) {
                    let id_str = peer_id.to_string();
                    let _ = table.remove(id_str.as_str());
                }
                let _ = txn.commit();
            }
        }
    }

    pub fn can_add_peer(&self, address: &str) -> bool {
        let Ok(multiaddr) = address.parse::<Multiaddr>() else {
            return false; // fail closed
        };

        self.check_ip_prefix_limit(&multiaddr, MAX_PEERS_PER_SUBNET)
    }

    pub fn add_peer(&mut self, peer: Peer) -> bool {
        // If the peer already exists in peer store, update address and last seen, but NEVER reset reputation
        if let Some(existing) = self.peers.get_mut(&peer.peer_id) {
            existing.address = peer.address;
            existing.update_last_seen();
            if existing.is_banned() {
                return false;
            }
            return true;
        }

        if !self.can_add_peer(&peer.address) {
            return false;
        }
        self.peers.insert(peer.peer_id, peer);
        true
    }

    /// Remove a peer from the in-memory store.
    ///
    /// SECURITY: banned peers are never fully forgotten — the entry is
    /// replaced with a ban-carrying stub so a disconnect/reconnect cycle
    /// cannot reset the peer's reputation and bypass the ban. Persistent bans
    /// live in the redb table; this preserves them in memory for the
    /// connection-admission checks.
    pub fn remove_peer(&mut self, peer_id: &PeerId) -> Option<Peer> {
        let removed = self.peers.remove(peer_id)?;
        if removed.is_banned() {
            let mut stub = Peer::new(removed.peer_id, "/ip4/0.0.0.0/tcp/0".parse().unwrap());
            stub.reputation = BANNED_REPUTATION_THRESHOLD;
            stub.address.clear(); // no usable address on the stub
            self.peers.insert(*peer_id, stub);
        }
        Some(removed)
    }

    pub fn get_peer(&self, peer_id: &PeerId) -> Option<&Peer> {
        self.peers.get(peer_id)
    }

    pub fn get_peer_mut(&mut self, peer_id: &PeerId) -> Option<&mut Peer> {
        self.peers.get_mut(peer_id)
    }

    pub fn connected_peers(&self) -> Vec<&Peer> {
        self.peers
            .values()
            .filter(|peer| !peer.is_banned())
            .collect()
    }

    /// Ban a peer for the standard TTL.
    ///
    /// Always persists the ban to the durable store. If the peer is not
    /// currently tracked in memory, a stub entry carrying the ban is created
    /// so the ban survives disconnect/reconnect cycles within this process.
    /// Returns `true` — a ban was applied (the previous `false` on the stub
    /// path misled callers into treating successful bans as failures).
    pub fn ban_peer(&mut self, peer_id: &PeerId) -> bool {
        let entry = BanEntry {
            reason: "Peer banned by dynamic networking rules".to_string(),
            score: BANNED_REPUTATION_THRESHOLD,
            created_at: Peer::unix_timestamp(),
            expires_at: Some(Peer::unix_timestamp() + crate::BAN_DURATION_SECS), // 7 days TTL
        };

        self.save_ban_to_db(peer_id, &entry);

        if let Some(peer) = self.peers.get_mut(peer_id) {
            peer.reputation = BANNED_REPUTATION_THRESHOLD;
        } else {
            // Add a stub peer to keep track of the ban in memory
            let stub_addr = "/ip4/0.0.0.0/tcp/0"
                .parse()
                .unwrap_or_else(|_| Multiaddr::empty());
            let mut peer = Peer::new(*peer_id, stub_addr);
            peer.reputation = BANNED_REPUTATION_THRESHOLD;
            self.peers.insert(*peer_id, peer);
        }
        true
    }

    pub fn unban_peer(&mut self, peer_id: &PeerId) -> bool {
        self.remove_ban_from_db(peer_id);
        if let Some(peer) = self.peers.get_mut(peer_id) {
            if peer.is_banned() {
                peer.reputation = 0;
            }
            return true;
        }
        false
    }

    pub fn penalize_invalid_message(&mut self, peer_id: &PeerId) -> bool {
        self.apply_penalty(peer_id, INVALID_MESSAGE_PENALTY)
    }

    pub fn penalize_duplicate_message(&mut self, peer_id: &PeerId) -> bool {
        self.apply_penalty(peer_id, DUPLICATE_MESSAGE_PENALTY)
    }

    pub fn penalize_rate_limit_violation(&mut self, peer_id: &PeerId) -> bool {
        self.apply_penalty(peer_id, RATE_LIMIT_PENALTY)
    }

    fn apply_penalty(&mut self, peer_id: &PeerId, amount: i32) -> bool {
        if let Some(peer) = self.peers.get_mut(peer_id) {
            peer.decrease_reputation(amount);
            if peer.is_banned() {
                peer.reputation = BANNED_REPUTATION_THRESHOLD;
                let entry = BanEntry {
                    reason: "Peer crossed reputation threshold via penalties".to_string(),
                    score: BANNED_REPUTATION_THRESHOLD,
                    created_at: Peer::unix_timestamp(),
                    expires_at: Some(Peer::unix_timestamp() + crate::BAN_DURATION_SECS),
                };
                self.save_ban_to_db(peer_id, &entry);
            }
            return true;
        }
        false
    }

    pub fn check_ip_prefix_limit(&self, address: &Multiaddr, limit: usize) -> bool {
        if let Some(ip_prefix) = get_ip_prefix(address) {
            let count = self
                .peers
                .values()
                .filter(|peer| {
                    if let Ok(addr) = peer.address.parse::<Multiaddr>() {
                        get_ip_prefix(&addr) == Some(ip_prefix.clone())
                    } else {
                        false
                    }
                })
                .count();
            count < limit
        } else {
            true
        }
    }
}

fn get_ip_prefix(address: &Multiaddr) -> Option<String> {
    use libp2p::multiaddr::Protocol;
    for proto in address.iter() {
        match proto {
            Protocol::Ip4(ip) => {
                let octets = ip.octets();
                return Some(format!("{}.{}.{}", octets[0], octets[1], octets[2]));
            }
            Protocol::Ip6(ip) => {
                let segments = ip.segments();
                return Some(format!(
                    "{:x}:{:x}:{:x}:{:x}",
                    segments[0], segments[1], segments[2], segments[3]
                ));
            }
            _ => {}
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::{Peer, PeerStore};
    use libp2p::{identity::Keypair, Multiaddr, PeerId};

    fn peer_id(seed: u8) -> PeerId {
        let mut bytes = [seed; 32];
        bytes[0] = bytes[0].max(1);
        PeerId::from(
            Keypair::ed25519_from_bytes(bytes)
                .expect("keypair should build")
                .public(),
        )
    }

    fn address(port: u16) -> Multiaddr {
        format!("/ip4/127.0.0.1/tcp/{port}")
            .parse()
            .expect("multiaddr should parse")
    }

    #[test]
    fn peer_new_update_last_seen_and_reputation_methods_work() {
        let peer_id = peer_id(1);
        let mut peer = Peer::new(peer_id, address(9001));

        assert_eq!(peer.peer_id, peer_id);
        assert_eq!(peer.address, "/ip4/127.0.0.1/tcp/9001");
        assert_eq!(peer.reputation, 0);
        assert!(!peer.is_banned());
        assert!(peer.last_seen > 0);

        let initial_last_seen = peer.last_seen;
        peer.update_last_seen();
        assert!(peer.last_seen >= initial_last_seen);

        peer.increase_reputation(15);
        assert_eq!(peer.reputation, 15);
        peer.increase_reputation(-10);
        assert_eq!(peer.reputation, 15);

        peer.decrease_reputation(20);
        assert_eq!(peer.reputation, -5);
        peer.decrease_reputation(-20);
        assert_eq!(peer.reputation, -5);

        peer.decrease_reputation(200);
        assert!(peer.is_banned());
    }

    #[test]
    fn peer_store_add_remove_get_connected_ban_and_unban_work() {
        let first_id = peer_id(2);
        let second_id = peer_id(3);
        let first_peer = Peer::new(first_id, address(9002));
        let second_peer = Peer::new(second_id, address(9003));
        let mut store = PeerStore::default();

        store.add_peer(first_peer.clone());
        store.add_peer(second_peer.clone());

        assert_eq!(
            store.get_peer(&first_id).map(|peer| peer.address.as_str()),
            Some("/ip4/127.0.0.1/tcp/9002")
        );
        assert_eq!(store.connected_peers().len(), 2);

        assert!(store.ban_peer(&first_id));
        assert!(store
            .get_peer(&first_id)
            .expect("peer should exist")
            .is_banned());
        assert_eq!(store.connected_peers().len(), 1);
        assert_eq!(store.connected_peers()[0].peer_id, second_id);

        assert!(store.unban_peer(&first_id));
        assert!(!store
            .get_peer(&first_id)
            .expect("peer should exist")
            .is_banned());
        assert_eq!(store.connected_peers().len(), 2);

        let removed = store
            .remove_peer(&second_id)
            .expect("peer should be removed");
        assert_eq!(removed.peer_id, second_id);
        assert!(store.get_peer(&second_id).is_none());
        assert_eq!(store.connected_peers().len(), 1);
    }

    #[test]
    fn can_add_peer_fails_closed_on_invalid_multiaddr() {
        let store = PeerStore::default();
        assert!(!store.can_add_peer("invalid_address"));
    }

    #[test]
    fn can_add_peer_enforces_ip_prefix_limit() {
        let mut store = PeerStore::default();
        let max_peers = super::MAX_PEERS_PER_SUBNET;

        // Add maximum allowed peers for the same /24 prefix (127.0.0.x)
        for i in 0..max_peers {
            let id = peer_id(i as u8);
            let addr = format!("/ip4/127.0.0.{}/tcp/9000", i);
            let peer = Peer::new(id, addr.parse().unwrap());
            assert!(store.add_peer(peer), "Should add peer {}", i);
        }

        // Next peer in the same prefix should be rejected
        let id_rej = peer_id(max_peers as u8);
        let addr_rej = format!("/ip4/127.0.0.{}/tcp/9000", max_peers + 1);
        let peer_rej = Peer::new(id_rej, addr_rej.parse().unwrap());

        assert!(
            !store.can_add_peer(&peer_rej.address),
            "Should reject peer over limit"
        );
        assert!(
            !store.add_peer(peer_rej),
            "Should fail to add peer over limit"
        );

        // But a peer in a different prefix should be allowed
        let addr_diff = "/ip4/127.0.1.1/tcp/9000";
        assert!(
            store.can_add_peer(addr_diff),
            "Should allow peer in different prefix"
        );
    }

    #[test]
    fn banned_peer_cannot_reset_reputation_by_reconnecting() {
        let id = peer_id(10);
        let mut store = PeerStore::default();
        let peer = Peer::new(id, address(9010));
        assert!(store.add_peer(peer));

        assert!(store.ban_peer(&id));
        assert!(store.get_peer(&id).unwrap().is_banned());

        // Attempt to re-add peer as if reconnecting
        let reconnecting_peer = Peer::new(id, address(9011));
        assert!(!store.add_peer(reconnecting_peer));

        // Must still be banned with threshold reputation
        let current = store.get_peer(&id).unwrap();
        assert!(current.is_banned());
        assert_eq!(current.reputation, super::BANNED_REPUTATION_THRESHOLD);
    }

    // SECURITY REGRESSION: a banned peer used to be fully forgotten on
    // disconnect (remove_peer), letting it reconnect with a fresh reputation
    // even though a persistent ban existed. The store must retain a
    // ban-carrying stub so connection admission keeps rejecting it.
    #[test]
    fn ban_survives_disconnect_and_reconnect_cycle() {
        let id = peer_id(11);
        let mut store = PeerStore::default();
        store.add_peer(Peer::new(id, address(9012)));
        assert!(store.ban_peer(&id));

        // Node observes the disconnect and drops the live entry.
        store.remove_peer(&id).expect("peer should be removed");

        // The ban must still be enforced for a fresh inbound connection.
        assert!(
            !store.add_peer(Peer::new(id, address(9013))),
            "banned peer must not be re-admitted after reconnect"
        );
        let stub = store.get_peer(&id).expect("ban stub should persist");
        assert!(stub.is_banned());
        assert_eq!(stub.reputation, super::BANNED_REPUTATION_THRESHOLD);
    }

    #[test]
    fn ban_peer_reports_success_even_for_unknown_peer() {
        let mut store = PeerStore::default();
        let unknown = peer_id(12);
        // Ban applied via durable store + stub; must not report failure.
        assert!(store.ban_peer(&unknown));
        let stub = store.get_peer(&unknown).expect("stub created");
        assert!(stub.is_banned());
        assert_eq!(store.connected_peers().len(), 0);
    }
}
