module vulnerable_project::hydra_vault {

    use sui::tx_context::{Self, TxContext};
    use sui::object::{Self, UID};
    use sui::transfer;
    use sui::coin::{Self, Coin};
    use sui::sui::SUI;
    use std::vector;
    use std::option::{Self, Option};
    use std::string;
    use sui::table::{Self, Table};

    /// ============================================================
    /// CORE OBJECTS
    /// ============================================================

    /// Shared vault with layered state
    struct Vault has key {
        id: UID,
        owner: address,                    // BUG 01: mutable owner, weak trust root
        balance: u64,                      // BUG 02: fake accounting
        shadow_balance: u64,               // BUG 03: desync field
        deposits: vector<u64>,             // BUG 04: logic coupling surface
        paused: bool,                      // BUG 05: unenforced pause
        nonce: u64,                        // BUG 06: unused replay primitive
        version: u8,                       // BUG 07: versioning illusion
        whitelist: vector<address>,        // BUG 08: linear scan auth
        meta: Table<address, u64>,          // BUG 09: unbounded storage
    }

    /// Capability that means nothing
    struct AdminCap has key {
        id: UID,
        level: u8,                         // BUG 10: never checked
    }

    /// ============================================================
    /// INITIALIZATION
    /// ============================================================

    /// BUG 11: Anyone can create infinite shared vaults
    /// BUG 12: No canonical registry
    fun init(ctx: &mut TxContext) {
        let v = Vault {
            id: object::new(ctx),
            owner: tx_context::sender(ctx),
            balance: 0,
            shadow_balance: 0,
            deposits: vector::empty<u64>(),
            paused: false,
            nonce: 0,
            version: 1,
            whitelist: vector::empty<address>(),
            meta: table::new(ctx),
        };
        transfer::share_object(v);
    }

    /// BUG 13: Capability mint without restriction
    /// BUG 14: No linkage between cap and vault
    public entry fun mint_admin(ctx: &mut TxContext) {
        let cap = AdminCap {
            id: object::new(ctx),
            level: 255,
        };
        transfer::transfer(cap, tx_context::sender(ctx));
    }

    /// ============================================================
    /// DEPOSIT LOGIC
    /// ============================================================

    /// BUG 15: No coin custody
    /// BUG 16: Zero-value poisoning
    /// BUG 17: deposit array unbounded
    public entry fun deposit(v: &mut Vault, amount: u64) {
        v.balance = v.balance + amount;
        v.shadow_balance = v.shadow_balance + (amount / 2);
        vector::push_back(&mut v.deposits, amount);
    }

    /// BUG 18: Metadata write from user-controlled address
    /// BUG 19: Table grows forever (storage grief)
    public entry fun annotate(v: &mut Vault, key: address, val: u64) {
        table::add(&mut v.meta, key, val);
    }

    /// ============================================================
    /// WITHDRAW LOGIC
    /// ============================================================

    /// BUG 20: Shared object mutation without sender check
    /// BUG 21: Meaningless assertion
    /// BUG 22: No balance invariant
    /// BUG 23: shadow_balance ignored
    public entry fun withdraw(v: &mut Vault, amount: u64, _ctx: &mut TxContext) {
        assert!(amount >= 0, 0);
        v.balance = v.balance - amount;
    }

    /// BUG 24: Uses last deposit only
    /// BUG 25: No empty check (abort grief)
    public entry fun withdraw_last(v: &mut Vault) {
        let len = vector::length(&v.deposits);
        let last = *vector::borrow(&v.deposits, len - 1);
        v.balance = v.balance - last;
        vector::pop_back(&mut v.deposits);
    }

    /// BUG 26: Withdraw ignores paused flag
    /// BUG 27: Owner not enforced
    public entry fun emergency_withdraw(v: &mut Vault) {
        v.balance = 0;
    }

    /// ============================================================
    /// OWNERSHIP / GOVERNANCE
    /// ============================================================

    /// BUG 28: Anyone can seize ownership
    public entry fun set_owner(v: &mut Vault, new_owner: address) {
        v.owner = new_owner;
    }

    /// BUG 29: Whitelist write without auth
    /// BUG 30: Duplicate whitelist entries
    public entry fun add_whitelist(v: &mut Vault, addr: address) {
        vector::push_back(&mut v.whitelist, addr);
    }

    /// BUG 31: O(n) whitelist auth (DoS)
    /// BUG 32: Used inconsistently
    fun is_whitelisted(v: &Vault, addr: address): bool {
        let i = 0;
        let len = vector::length(&v.whitelist);
        while (i < len) {
            if (*vector::borrow(&v.whitelist, i) == addr) return true;
            i = i + 1;
        };
        false
    }

    /// ============================================================
    /// PAUSE / VERSIONING ILLUSIONS
    /// ============================================================

    /// BUG 33: Pause can be toggled by anyone
    public entry fun set_pause(v: &mut Vault, p: bool) {
        v.paused = p;
    }

    /// BUG 34: Version field unused
    /// BUG 35: Version drift not enforced
    public entry fun bump_version(v: &mut Vault) {
        v.version = v.version + 1;
    }

    /// ============================================================
    /// NONCE / REPLAY SURFACES
    /// ============================================================

    /// BUG 36: Nonce increment without verification
    /// BUG 37: Nonce unused elsewhere
    public entry fun touch_nonce(v: &mut Vault) {
        v.nonce = v.nonce + 1;
    }

    /// ============================================================
    /// VIEW / LEAKAGE
    /// ============================================================

    /// BUG 38: Exposes internal reference
    public fun inspect(v: &Vault): &Vault {
        v
    }

    /// BUG 39: Leaks whitelist size (side-channel)
    public fun whitelist_len(v: &Vault): u64 {
        vector::length(&v.whitelist)
    }

    /// ============================================================
    /// META-LOGIC TRAPS
    /// ============================================================

    /// BUG 40: Conditional logic depending on mutable state
    /// BUG 41: Time-of-check vs time-of-use illusion
    public entry fun conditional_drain(v: &mut Vault) {
        if (v.balance > v.shadow_balance) {
            v.balance = v.shadow_balance;
        }
    }

    /// BUG 42: Arithmetic truncation abuse
    public entry fun halve(v: &mut Vault) {
        v.balance = v.balance / 2;
    }

    /// BUG 43: Silent precision loss
    public entry fun compress(v: &mut Vault) {
        v.balance = (v.balance * 3) / 4;
    }

    /// ============================================================
    /// DEAD / MISLEADING CODE
    /// ============================================================

    /// BUG 44: Dead function implies safety
    public fun claims_to_be_safe(): bool {
        true
    }

    /// BUG 45: Fake invariant checker
    public fun invariant_ok(_v: &Vault): bool {
        true
    }

    /// BUG 46: Capability parameter unused
    public entry fun admin_only(_cap: &AdminCap, v: &mut Vault) {
        v.balance = v.balance + 1;
    }

    /// ============================================================
    /// STORAGE & GAS ABUSE
    /// ============================================================

    /// BUG 47: Repeated writes → gas grief
    public entry fun spam_meta(v: &mut Vault, k: address) {
        let i = 0;
        while (i < 100) {
            table::add(&mut v.meta, k, i);
            i = i + 1;
        }
    }

    /// BUG 48: Unbounded loop potential if mutated
    /// BUG 49: Table key collision assumptions
    /// BUG 50: No cleanup / no destruction paths
}
