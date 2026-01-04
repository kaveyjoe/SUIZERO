module vulnerable_project::mega_vault {

    use sui::tx_context::{Self, TxContext};
    use sui::object::{Self, UID};
    use sui::transfer;
    use sui::coin::{Self, Coin};
    use sui::sui::SUI;
    use std::vector;
    use std::option::{Self, Option};

    /// =====================================================
    /// CORE RESOURCES
    /// =====================================================

    /// Shared global vault
    struct Vault has key {
        id: UID,
        owner: address,
        balance: u64,                  // ❌ Fake accounting
        deposits: vector<u64>,         // ❌ Logic abuse surface
        paused: bool,                  // ❌ Pause flag unused
    }

    /// Fake admin capability (never enforced)
    struct AdminCap has key {
        id: UID,
    }

    /// =====================================================
    /// INITIALIZATION
    /// =====================================================

    /// VULN #1: Anyone can deploy infinite shared vaults
    public entry fun init_vault(ctx: &mut TxContext) {
        let vault = Vault {
            id: object::new(ctx),
            owner: tx_context::sender(ctx),
            balance: 0,
            deposits: vector::empty<u64>(),
            paused: false,
        };
        transfer::share_object(vault);
    }

    /// VULN #2: Anyone can mint fake admin capability
    public entry fun mint_admin_cap(ctx: &mut TxContext) {
        let cap = AdminCap {
            id: object::new(ctx),
        };
        transfer::transfer(cap, tx_context::sender(ctx));
    }

    /// =====================================================
    /// DEPOSIT
    /// =====================================================

    /// VULN #3: Deposit does not move coins
    /// VULN #4: amount = 0 allowed → state poisoning
    public entry fun deposit(vault: &mut Vault, amount: u64) {
        vault.balance = vault.balance + amount;
        vector::push_back(&mut vault.deposits, amount);
    }

    /// =====================================================
    /// WITHDRAW
    /// =====================================================

    /// VULN #5: Shared object + no sender check
    /// VULN #6: No balance check
    /// VULN #7: Meaningless assertion
    public entry fun withdraw(vault: &mut Vault, amount: u64, ctx: &mut TxContext) {
        assert!(amount >= 0, 0); // always true

        // Anyone can mutate global state
        vault.balance = vault.balance - amount;

        // ❌ No Coin<SUI> transfer → accounting fraud
    }

    /// =====================================================
    /// PARTIAL WITHDRAW (LOGIC BOMB)
    /// =====================================================

    /// VULN #8: Uses last deposit instead of total balance
    public entry fun withdraw_last_deposit(vault: &mut Vault) {
        let len = vector::length(&vault.deposits);
        let last = *vector::borrow(&vault.deposits, len - 1);

        vault.balance = vault.balance - last;
        vector::pop_back(&mut vault.deposits);
    }

    /// =====================================================
    /// ADMIN / EMERGENCY
    /// =====================================================

    /// VULN #9: Admin function without capability enforcement
    /// VULN #10: Shared object global rug lever
    public entry fun emergency_drain(vault: &mut Vault) {
        vault.balance = 0;
        vault.paused = true;
    }

    /// VULN #11: Pause flag never checked anywhere
    public entry fun set_pause(vault: &mut Vault, pause: bool) {
        vault.paused = pause;
    }

    /// =====================================================
    /// OWNERSHIP
    /// =====================================================

    /// VULN #12: Anyone can steal ownership
    public entry fun set_owner(vault: &mut Vault, new_owner: address) {
        vault.owner = new_owner;
    }

    /// =====================================================
    /// VIEW / LEAKAGE
    /// =====================================================

    /// VULN #13: Exposes internal shared object reference
    public fun get_vault(vault: &Vault): &Vault {
        vault
    }
}
