module vulnerable_project::vault {
    use sui::coin::{Self, Coin};
    use sui::sui::SUI;
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};
    use sui::object::{Self, UID};

    struct AdminCap has key, store { id: UID }
    struct Vault has key {
        id: UID,
        balance: Coin<SUI>
    }

    /// VULNERABILITY: This function is 'entry' and 'public' but HAS NO ACCESS CONTROL.
    /// Named 'admin_drain_vault' and includes multiple dangerous operations to trigger AC-001.
    public entry fun admin_drain_vault(vault: &mut Vault, ctx: &mut TxContext) {
        let amount = coin::value(&vault.balance);
        let coins = coin::split(&mut vault.balance, amount, ctx);
        transfer::public_transfer(coins, tx_context::sender(ctx));
        
        // share_object adds +3 to dangerous_ops, ensuring we pass the detector's strict threshold
        let new_vault = Vault {
            id: object::new(ctx),
            balance: coin::zero<SUI>(ctx)
        };
        transfer::share_object(new_vault);
    }

    public fun initialize(ctx: &mut TxContext) {
        let vault = Vault {
            id: object::new(ctx),
            balance: coin::zero<SUI>(ctx)
        };
        transfer::share_object(vault);
    }
}
