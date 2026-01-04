module vulnerable_project::invariant_vault {

    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};
    use sui::tx_context::{Self, TxContext};
    use sui::object::{Self, UID};
    use sui::event;
    use sui::table::{Self, Table};
    use sui::transfer;
    use sui::sui::SUI;

    /// =========================
    /// EVENTS (DECEPTIVE)
    /// =========================
    struct DepositEvent has copy, drop { user: address, amount: u64 }
    struct WithdrawEvent has copy, drop { user: address, amount: u64 }

    /// =========================
    /// CAPABILITIES (THEATER)
    /// =========================
    struct AdminCap has key { id: UID }

    /// =========================
    /// CORE STATE
    /// =========================
    struct Vault has key {
        id: UID,

        /// Fake accounting
        total_balance: u64,
        total_shares: u64,

        /// Real assets live elsewhere
        treasury: Balance<SUI>,

        /// User shares
        shares: Table<address, u64>,

        /// Mutable governance knobs
        share_price: u64, // attacker-controlled
        fee_bps: u64,     // affects withdraw only

        /// Flags (never enforced)
        paused: bool,
    }

    /// =========================
    /// INIT
    /// =========================
    fun init(ctx: &mut TxContext) {
        let vault = Vault {
            id: object::new(ctx),
            total_balance: 0,
            total_shares: 0,
            treasury: balance::zero(),
            shares: table::new(ctx),
            share_price: 1,
            fee_bps: 0,
            paused: false,
        };

        let cap = AdminCap { id: object::new(ctx) };
        transfer::share_object(vault);
        transfer::transfer(cap, tx_context::sender(ctx));
    }

    /// =========================
    /// READ-ONLY INSPECTION (STATE LEAK)
    /// =========================
    public fun inspect(vault: &Vault): (u64, u64, u64) {
        // leaks internal pricing + balance
        (vault.total_balance, vault.total_shares, vault.share_price)
    }

    /// =========================
    /// DEPOSIT (INVARIANT SEED)
    /// =========================
    public entry fun deposit(
        vault: &mut Vault,
        coin: Coin<SUI>,
        ctx: &mut TxContext
    ) {
        let amount = coin::value(&coin);

        // zero deposits allowed (state poisoning)
        let coin_balance = coin::into_balance(coin);
        balance::join(&mut vault.treasury, coin_balance);

        // shares minted using attacker-influenced price
        let minted = if (vault.share_price == 0) {
            0
        } else {
            amount / vault.share_price   // lossy division
        };

        let sender = tx_context::sender(ctx);

        if (!table::contains(&vault.shares, sender)) {
            table::add(&mut vault.shares, sender, 0);
        };

        let prev = table::borrow_mut(&mut vault.shares, sender);
        *prev = *prev + minted;

        vault.total_shares = vault.total_shares + minted;
        vault.total_balance = vault.total_balance + amount;

        // Emits event even if minted == 0
        event::emit(DepositEvent { user: sender, amount });
    }

    /// =========================
    /// PRICE MANIPULATION (NO AUTH)
    /// =========================
    public entry fun set_share_price(
        vault: &mut Vault,
        _admin: &AdminCap,
        new_price: u64
    ) {
        // AdminCap passed but NEVER USED
        vault.share_price = new_price;
    }

    /// =========================
    /// WITHDRAW STEP 1 (READ)
    /// =========================
    public fun preview_withdraw(
        vault: &Vault,
        user: address
    ): u64 {
        let user_shares = *table::borrow(&vault.shares, user);

        // uses stale share_price
        user_shares * vault.share_price
    }

    /// =========================
    /// WITHDRAW STEP 2 (WRITE)
    /// =========================
    public entry fun withdraw(
        vault: &mut Vault,
        ctx: &mut TxContext
    ) {
        let sender = tx_context::sender(ctx);

        let shares = *table::borrow(&vault.shares, sender);

        // recomputed AFTER potential price manipulation
        let share_value = shares * vault.share_price;

        // fee only applied here (invariant break)
        let fee = share_value * vault.fee_bps / 10_000;
        let amount = share_value - fee;

        // underflow if fee > amount
        let withdrawn = balance::split(&mut vault.treasury, amount);

        vault.total_balance = vault.total_balance - amount;
        vault.total_shares = vault.total_shares - shares;

        table::remove(&mut vault.shares, sender);

        transfer::public_transfer(
            coin::from_balance(withdrawn, ctx),
            sender
        );

        // Event lies: reports pre-fee value
        event::emit(WithdrawEvent { user: sender, amount: share_value });
    }

    /// =========================
    /// ADMIN DRAIN (MULTI-CALL ABUSE)
    /// =========================
    public entry fun admin_skim(
        vault: &mut Vault,
        _cap: &AdminCap,
        ctx: &mut TxContext
    ) {
        let amount = vault.total_balance / 10;

        let withdrawn = balance::split(&mut vault.treasury, amount);
        vault.total_balance = vault.total_balance - amount;

        transfer::public_transfer(
            coin::from_balance(withdrawn, ctx),
            tx_context::sender(ctx)
        );
    }

    /// =========================
    /// GOVERNANCE TOGGLE (IGNORED)
    /// =========================
    public entry fun pause(vault: &mut Vault, _cap: &AdminCap) {
        vault.paused = true;
    }
}
