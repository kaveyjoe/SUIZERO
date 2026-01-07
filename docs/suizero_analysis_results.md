```
=== SUI Security Analyzer ===
Analyzing: ./examples/vulnerable_project/build/vulnerable_project/bytecode_modules
⠏ Analysis complete!                                                                                     +------------+----------+--------------------------+--------------------------+-------------------------+
| ID         | Severity | Title                    | Location                 | Description             |
+=======================================================================================================+
| SUI-027    | High     | Capability Theater       | vault::admin_drain_vault | The capability struct   |
|            |          |                          |                          | 'AdminCap' exists but   |
|            |          |                          |                          | is never used for       |
|            |          |                          |                          | authentication in any   |
|            |          |                          |                          | sensitive functi        |
|------------+----------+--------------------------+--------------------------+-------------------------|
| SUI-031    | Medium   | Unbound Capability       | vault::admin_drain_vault | Capability struct       |
|            |          |                          |                          | 'AdminCap' has no       |
|            |          |                          |                          | binding fields. It      |
|            |          |                          |                          | should ideally contain  |
|            |          |                          |                          | the ID of the object i  |
|------------+----------+--------------------------+--------------------------+-------------------------|
| AC-001     | Critical | Missing Sender           | vault::admin_drain_vault | Critical function lacks |
|            |          | Validation in            |                          | sender validation and   |
|            |          | 'admin_drain_vault'      |                          | could be called by      |
|            |          |                          |                          | anyone                  |
|------------+----------+--------------------------+--------------------------+-------------------------|
| SUI-022    | Critical | Unprotected Shared       | vault::admin_drain_vault | Function takes a        |
|            |          | Object Mutation          |                          | mutable reference to a  |
|            |          |                          |                          | struct and modifies it  |
|            |          |                          |                          | without verifying the   |
|            |          |                          |                          | sender. On Sui,         |
|------------+----------+--------------------------+--------------------------+-------------------------|
| SUI-021    | Critical | Unrestricted Shared      | vault::admin_drain_vault | Entry function shares   |
|            |          | Object Initialization    |                          | an object without any   |
|            |          |                          |                          | visible access control  |
|            |          |                          |                          | or capability check.    |
|            |          |                          |                          | This may all            |
|------------+----------+--------------------------+--------------------------+-------------------------|
| EXT-AC-007 | Critical | Admin function without   | vault::admin_drain_vault | Admin function          |
|            |          | capability               |                          | 'admin_drain_vault'     |
|            |          |                          |                          | lacks capability check  |
|------------+----------+--------------------------+--------------------------+-------------------------|
| ARITH-003  | Critical | Unchecked subtraction    | invariant_vault::withdra | Subtraction without     |
|            |          | may underflow            | w                        | underflow protection    |
|------------+----------+--------------------------+--------------------------+-------------------------|
| ARITH-003  | Critical | Unchecked subtraction    | invariant_vault::withdra | Subtraction without     |
|            |          | may underflow            | w                        | underflow protection    |
|------------+----------+--------------------------+--------------------------+-------------------------|
| ARITH-003  | Critical | Unchecked subtraction    | invariant_vault::withdra | Subtraction without     |
|            |          | may underflow            | w                        | underflow protection    |
|------------+----------+--------------------------+--------------------------+-------------------------|
| ARITH-003  | Critical | Unchecked subtraction    | invariant_vault::admin_s | Subtraction without     |
|            |          | may underflow            | kim                      | underflow protection    |
|------------+----------+--------------------------+--------------------------+-------------------------|
| SUI-030    | High     | Unbounded Table/Bag      | invariant_vault::init    | Function 'deposit' adds |
|            |          | Storage                  |                          | entries to a Table/Bag  |
|            |          |                          |                          | without an apparent     |
|            |          |                          |                          | size limit. This can    |
|            |          |                          |                          | lead to unbo            |
|------------+----------+--------------------------+--------------------------+-------------------------|
| SUI-031    | Medium   | Unbound Capability       | invariant_vault::init    | Capability struct       |
|            |          |                          |                          | 'AdminCap' has no       |
|            |          |                          |                          | binding fields. It      |
|            |          |                          |                          | should ideally contain  |
|            |          |                          |                          | the ID of the object i  |
|------------+----------+--------------------------+--------------------------+-------------------------|
| SUI-026    | Medium   | Zero-Amount Deposit      | invariant_vault::deposit | Function 'deposit'      |
|            |          | State Poisoning          |                          | allows zero-amount      |
|            |          |                          |                          | deposits. This can lead |
|            |          |                          |                          | to state poisoning,     |
|            |          |                          |                          | unnecessary vector      |
|------------+----------+--------------------------+--------------------------+-------------------------|
| SUI-025    | High     | Pause Flag Illusion      | invariant_vault::init    | The field 'paused' is   |
|            |          |                          |                          | defined and likely      |
|            |          |                          |                          | settable, but its value |
|            |          |                          |                          | is never checked in any |
|            |          |                          |                          | conditional             |
|------------+----------+--------------------------+--------------------------+-------------------------|
| ARITH-005  | Critical | Division without zero    | invariant_vault::deposit | Division may cause      |
|            |          | check                    |                          | panic if divisor is     |
|            |          |                          |                          | zero                    |
|------------+----------+--------------------------+--------------------------+-------------------------|
| SUI-022    | Critical | Unprotected Shared       | invariant_vault::set_sha | Function takes a        |
|            |          | Object Mutation          | re_price                 | mutable reference to a  |
|            |          |                          |                          | struct and modifies it  |
|            |          |                          |                          | without verifying the   |
|            |          |                          |                          | sender. On Sui,         |
|------------+----------+--------------------------+--------------------------+-------------------------|
| SUI-022    | Critical | Unprotected Shared       | invariant_vault::withdra | Function takes a        |
|            |          | Object Mutation          | w                        | mutable reference to a  |
|            |          |                          |                          | struct and modifies it  |
|            |          |                          |                          | without verifying the   |
|            |          |                          |                          | sender. On Sui,         |
|------------+----------+--------------------------+--------------------------+-------------------------|
| SUI-022    | Critical | Unprotected Shared       | invariant_vault::admin_s | Function takes a        |
|            |          | Object Mutation          | kim                      | mutable reference to a  |
|            |          |                          |                          | struct and modifies it  |
|            |          |                          |                          | without verifying the   |
|            |          |                          |                          | sender. On Sui,         |
|------------+----------+--------------------------+--------------------------+-------------------------|
| SUI-022    | Critical | Unprotected Shared       | invariant_vault::pause   | Function takes a        |
|            |          | Object Mutation          |                          | mutable reference to a  |
|            |          |                          |                          | struct and modifies it  |
|            |          |                          |                          | without verifying the   |
|            |          |                          |                          | sender. On Sui,         |
|------------+----------+--------------------------+--------------------------+-------------------------|
| SUI-033    | Critical | Phantom Authorization    | invariant_vault::init    | Function                |
|            |          | Parameter                |                          | 'set_share_price' has a |
|            |          |                          |                          | capability parameter    |
|            |          |                          |                          | 'AdminCap' that is      |
|            |          |                          |                          | NEVER USED in the       |
|            |          |                          |                          | function                |
|------------+----------+--------------------------+--------------------------+-------------------------|
| SUI-033    | Critical | Phantom Authorization    | invariant_vault::init    | Function 'admin_skim'   |
|            |          | Parameter                |                          | has a capability        |
|            |          |                          |                          | parameter 'AdminCap'    |
|            |          |                          |                          | that is NEVER USED in   |
|            |          |                          |                          | the function body.      |
|------------+----------+--------------------------+--------------------------+-------------------------|
| SUI-033    | Critical | Phantom Authorization    | invariant_vault::init    | Function 'pause' has a  |
|            |          | Parameter                |                          | capability parameter    |
|            |          |                          |                          | 'AdminCap' that is      |
|            |          |                          |                          | NEVER USED in the       |
|            |          |                          |                          | function body. This     |
|------------+----------+--------------------------+--------------------------+-------------------------|
| SUI-036    | High     | Potential TOCTOU /       | invariant_vault::preview | Field #2 is part of a   |
|            |          | Front-Running            | _withdraw                | TOCTOU triad.           |
|            |          | Vulnerability            |                          | 1. Inspected by:        |
|            |          |                          |                          | ["inspect",             |
|            |          |                          |                          | "preview_withdraw"]     |
|            |          |                          |                          | 2. Mutated by:          |
|------------+----------+--------------------------+--------------------------+-------------------------|
| SUI-036    | High     | Potential TOCTOU /       | invariant_vault::withdra | Field #2 is part of a   |
|            |          | Front-Running            | w                        | TOCTOU triad.           |
|            |          | Vulnerability            |                          | 1. Inspected by:        |
|            |          |                          |                          | ["inspect",             |
|            |          |                          |                          | "preview_withdraw"]     |
|            |          |                          |                          | 2. Mutated by:          |
|------------+----------+--------------------------+--------------------------+-------------------------|
| ARITH-002  | Critical | Unchecked multiplication | invariant_vault::preview | Multiplication without  |
|            |          | may overflow             | _withdraw                | overflow checks         |
|------------+----------+--------------------------+--------------------------+-------------------------|
| ARITH-002  | Critical | Unchecked multiplication | invariant_vault::withdra | Multiplication without  |
|            |          | may overflow             | w                        | overflow checks         |
|------------+----------+--------------------------+--------------------------+-------------------------|
| FIN-004    | Critical | Liquidity drain risk in  | invariant_vault::preview | Withdrawal function     |
|            |          | 'preview_withdraw'       | _withdraw                | lacks limits allowing   |
|            |          |                          |                          | complete liquidity      |
|            |          |                          |                          | drain                   |
|------------+----------+--------------------------+--------------------------+-------------------------|
| FIN-004    | Critical | Liquidity drain risk in  | invariant_vault::withdra | Withdrawal function     |
|            |          | 'withdraw'               | w                        | lacks limits allowing   |
|            |          |                          |                          | complete liquidity      |
|            |          |                          |                          | drain                   |
|------------+----------+--------------------------+--------------------------+-------------------------|
| AC-CAP-001 | Critical | Unprotected Capability   | mega_vault::mint_admin_c | Function                |
|            |          | Minting                  | ap                       | 'mint_admin_cap' allows |
|            |          |                          |                          | anyone to mint a        |
|            |          |                          |                          | capability object.      |
|            |          |                          |                          | Capabilities should be  |
|            |          |                          |                          | strictly                |
|------------+----------+--------------------------+--------------------------+-------------------------|
| ARITH-003  | Critical | Unchecked subtraction    | mega_vault::withdraw_las | Subtraction without     |
|            |          | may underflow            | t_deposit                | underflow protection    |
|------------+----------+--------------------------+--------------------------+-------------------------|
| ARITH-003  | Critical | Unchecked subtraction    | mega_vault::withdraw_las | Subtraction without     |
|            |          | may underflow            | t_deposit                | underflow protection    |
|------------+----------+--------------------------+--------------------------+-------------------------|
| SUI-027    | High     | Capability Theater       | mega_vault::init_vault   | The capability struct   |
|            |          |                          |                          | 'AdminCap' exists but   |
|            |          |                          |                          | is never used for       |
|            |          |                          |                          | authentication in any   |
|            |          |                          |                          | sensitive functi        |
|------------+----------+--------------------------+--------------------------+-------------------------|
| SUI-024    | Critical | Fake Balance Accounting  | mega_vault::init_vault   | Struct 'vault' tracks a |
|            |          |                          |                          | balance using 'u64' but |
|            |          |                          |                          | does not hold any       |
|            |          |                          |                          | 'Coin<T>' or            |
|            |          |                          |                          | 'Balance<T>' objects.   |
|------------+----------+--------------------------+--------------------------+-------------------------|
| SUI-031    | Medium   | Unbound Capability       | mega_vault::init_vault   | Capability struct       |
|            |          |                          |                          | 'AdminCap' has no       |
|            |          |                          |                          | binding fields. It      |
|            |          |                          |                          | should ideally contain  |
|            |          |                          |                          | the ID of the object i  |
|------------+----------+--------------------------+--------------------------+-------------------------|
| SUI-026    | Medium   | Zero-Amount Deposit      | mega_vault::deposit      | Function 'deposit'      |
|            |          | State Poisoning          |                          | allows zero-amount      |
|            |          |                          |                          | deposits. This can lead |
|            |          |                          |                          | to state poisoning,     |
|            |          |                          |                          | unnecessary vector      |
|------------+----------+--------------------------+--------------------------+-------------------------|
| SUI-026    | Medium   | Zero-Amount Deposit      | mega_vault::withdraw_las | Function                |
|            |          | State Poisoning          | t_deposit                | 'withdraw_last_deposit' |
|            |          |                          |                          | allows zero-amount      |
|            |          |                          |                          | deposits. This can lead |
|            |          |                          |                          | to state poisoning,     |
|            |          |                          |                          | unne                    |
|------------+----------+--------------------------+--------------------------+-------------------------|
| SUI-023    | High     | Meaningless Assertion    | mega_vault::withdraw     | Detected 'assert!(x >=  |
|            |          |                          |                          | 0)' or similar on an    |
|            |          |                          |                          | unsigned integer (u64). |
|            |          |                          |                          | This check is always    |
|            |          |                          |                          | true and pr             |
|------------+----------+--------------------------+--------------------------+-------------------------|
| SUI-025    | High     | Pause Flag Illusion      | mega_vault::init_vault   | The field 'paused' is   |
|            |          |                          |                          | defined and likely      |
|            |          |                          |                          | settable, but its value |
|            |          |                          |                          | is never checked in any |
|            |          |                          |                          | conditional             |
|------------+----------+--------------------------+--------------------------+-------------------------|
| SUI-028    | Medium   | Internal Reference       | mega_vault::get_vault    | Public function         |
|            |          | Exposure                 |                          | 'get_vault' returns a   |
|            |          |                          |                          | reference to a struct.  |
|            |          |                          |                          | This may leak internal  |
|            |          |                          |                          | protocol state o        |
|------------+----------+--------------------------+--------------------------+-------------------------|
| SUI-022    | Critical | Unprotected Shared       | mega_vault::deposit      | Function takes a        |
|            |          | Object Mutation          |                          | mutable reference to a  |
|            |          |                          |                          | struct and modifies it  |
|            |          |                          |                          | without verifying the   |
|            |          |                          |                          | sender. On Sui,         |
|------------+----------+--------------------------+--------------------------+-------------------------|
| SUI-022    | Critical | Unprotected Shared       | mega_vault::withdraw_las | Function takes a        |
|            |          | Object Mutation          | t_deposit                | mutable reference to a  |
|            |          |                          |                          | struct and modifies it  |
|            |          |                          |                          | without verifying the   |
|            |          |                          |                          | sender. On Sui,         |
|------------+----------+--------------------------+--------------------------+-------------------------|
| SUI-022    | Critical | Unprotected Shared       | mega_vault::emergency_dr | Function takes a        |
|            |          | Object Mutation          | ain                      | mutable reference to a  |
|            |          |                          |                          | struct and modifies it  |
|            |          |                          |                          | without verifying the   |
|            |          |                          |                          | sender. On Sui,         |
|------------+----------+--------------------------+--------------------------+-------------------------|
| SUI-022    | Critical | Unprotected Shared       | mega_vault::set_pause    | Function takes a        |
|            |          | Object Mutation          |                          | mutable reference to a  |
|            |          |                          |                          | struct and modifies it  |
|            |          |                          |                          | without verifying the   |
|            |          |                          |                          | sender. On Sui,         |
|------------+----------+--------------------------+--------------------------+-------------------------|
| SUI-022    | Critical | Unprotected Shared       | mega_vault::set_owner    | Function takes a        |
|            |          | Object Mutation          |                          | mutable reference to a  |
|            |          |                          |                          | struct and modifies it  |
|            |          |                          |                          | without verifying the   |
|            |          |                          |                          | sender. On Sui,         |
|------------+----------+--------------------------+--------------------------+-------------------------|
| SUI-021    | Critical | Unrestricted Shared      | mega_vault::init_vault   | Entry function shares   |
|            |          | Object Initialization    |                          | an object without any   |
|            |          |                          |                          | visible access control  |
|            |          |                          |                          | or capability check.    |
|            |          |                          |                          | This may all            |
|------------+----------+--------------------------+--------------------------+-------------------------|
| EXT-AC-007 | Critical | Admin function without   | mega_vault::emergency_dr | Admin function          |
|            |          | capability               | ain                      | 'emergency_drain' lacks |
|            |          |                          |                          | capability check        |
|------------+----------+--------------------------+--------------------------+-------------------------|
| FIN-004    | Critical | Liquidity drain risk in  | mega_vault::withdraw     | Withdrawal function     |
|            |          | 'withdraw'               |                          | lacks limits allowing   |
|            |          |                          |                          | complete liquidity      |
|            |          |                          |                          | drain                   |
|------------+----------+--------------------------+--------------------------+-------------------------|
| FIN-004    | Critical | Liquidity drain risk in  | mega_vault::withdraw_las | Withdrawal function     |
|            |          | 'withdraw_last_deposit'  | t_deposit                | lacks limits allowing   |
|            |          |                          |                          | complete liquidity      |
|            |          |                          |                          | drain                   |
|------------+----------+--------------------------+--------------------------+-------------------------|
| AC-CAP-001 | Critical | Unprotected Capability   | hydra_vault::mint_admin  | Function 'mint_admin'   |
|            |          | Minting                  |                          | allows anyone to mint a |
|            |          |                          |                          | capability object.      |
|            |          |                          |                          | Capabilities should be  |
|            |          |                          |                          | strictly pro            |
|------------+----------+--------------------------+--------------------------+-------------------------|
| ARITH-003  | Critical | Unchecked subtraction    | hydra_vault::withdraw_la | Subtraction without     |
|            |          | may underflow            | st                       | underflow protection    |
|------------+----------+--------------------------+--------------------------+-------------------------|
| ARITH-003  | Critical | Unchecked subtraction    | hydra_vault::withdraw_la | Subtraction without     |
|            |          | may underflow            | st                       | underflow protection    |
|------------+----------+--------------------------+--------------------------+-------------------------|
| SUI-030    | High     | Unbounded Table/Bag      | hydra_vault::init        | Function 'annotate'     |
|            |          | Storage                  |                          | adds entries to a       |
|            |          |                          |                          | Table/Bag without an    |
|            |          |                          |                          | apparent size limit.    |
|            |          |                          |                          | This can lead to unb    |
|------------+----------+--------------------------+--------------------------+-------------------------|
| SUI-030    | High     | Unbounded Table/Bag      | hydra_vault::init        | Function 'spam_meta'    |
|            |          | Storage                  |                          | adds entries to a       |
|            |          |                          |                          | Table/Bag without an    |
|            |          |                          |                          | apparent size limit.    |
|            |          |                          |                          | This can lead to un     |
|------------+----------+--------------------------+--------------------------+-------------------------|
| SUI-027    | High     | Capability Theater       | hydra_vault::init        | The capability struct   |
|            |          |                          |                          | 'AdminCap' exists but   |
|            |          |                          |                          | is never used for       |
|            |          |                          |                          | authentication in any   |
|            |          |                          |                          | sensitive functi        |
|------------+----------+--------------------------+--------------------------+-------------------------|
| SUI-024    | Critical | Fake Balance Accounting  | hydra_vault::init        | Struct 'vault' tracks a |
|            |          |                          |                          | balance using 'u64' but |
|            |          |                          |                          | does not hold any       |
|            |          |                          |                          | 'Coin<T>' or            |
|            |          |                          |                          | 'Balance<T>' objects.   |
|------------+----------+--------------------------+--------------------------+-------------------------|
| SUI-026    | Medium   | Zero-Amount Deposit      | hydra_vault::deposit     | Function 'deposit'      |
|            |          | State Poisoning          |                          | allows zero-amount      |
|            |          |                          |                          | deposits. This can lead |
|            |          |                          |                          | to state poisoning,     |
|            |          |                          |                          | unnecessary vector      |
|------------+----------+--------------------------+--------------------------+-------------------------|
| SUI-023    | High     | Meaningless Assertion    | hydra_vault::withdraw    | Detected 'assert!(x >=  |
|            |          |                          |                          | 0)' or similar on an    |
|            |          |                          |                          | unsigned integer (u64). |
|            |          |                          |                          | This check is always    |
|            |          |                          |                          | true and pr             |
|------------+----------+--------------------------+--------------------------+-------------------------|
| SUI-025    | High     | Pause Flag Illusion      | hydra_vault::init        | The field 'paused' is   |
|            |          |                          |                          | defined and likely      |
|            |          |                          |                          | settable, but its value |
|            |          |                          |                          | is never checked in any |
|            |          |                          |                          | conditional             |
|------------+----------+--------------------------+--------------------------+-------------------------|
| SUI-028    | Medium   | Internal Reference       | hydra_vault::inspect     | Public function         |
|            |          | Exposure                 |                          | 'inspect' returns a     |
|            |          |                          |                          | reference to a struct.  |
|            |          |                          |                          | This may leak internal  |
|            |          |                          |                          | protocol state or       |
|------------+----------+--------------------------+--------------------------+-------------------------|
| SUI-022    | Critical | Unprotected Shared       | hydra_vault::deposit     | Function takes a        |
|            |          | Object Mutation          |                          | mutable reference to a  |
|            |          |                          |                          | struct and modifies it  |
|            |          |                          |                          | without verifying the   |
|            |          |                          |                          | sender. On Sui,         |
|------------+----------+--------------------------+--------------------------+-------------------------|
| SUI-022    | Critical | Unprotected Shared       | hydra_vault::annotate    | Function takes a        |
|            |          | Object Mutation          |                          | mutable reference to a  |
|            |          |                          |                          | struct and modifies it  |
|            |          |                          |                          | without verifying the   |
|            |          |                          |                          | sender. On Sui,         |
|------------+----------+--------------------------+--------------------------+-------------------------|
| SUI-022    | Critical | Unprotected Shared       | hydra_vault::withdraw_la | Function takes a        |
|            |          | Object Mutation          | st                       | mutable reference to a  |
|            |          |                          |                          | struct and modifies it  |
|            |          |                          |                          | without verifying the   |
|            |          |                          |                          | sender. On Sui,         |
|------------+----------+--------------------------+--------------------------+-------------------------|
| SUI-022    | Critical | Unprotected Shared       | hydra_vault::emergency_w | Function takes a        |
|            |          | Object Mutation          | ithdraw                  | mutable reference to a  |
|            |          |                          |                          | struct and modifies it  |
|            |          |                          |                          | without verifying the   |
|            |          |                          |                          | sender. On Sui,         |
|------------+----------+--------------------------+--------------------------+-------------------------|
| SUI-022    | Critical | Unprotected Shared       | hydra_vault::set_owner   | Function takes a        |
|            |          | Object Mutation          |                          | mutable reference to a  |
|            |          |                          |                          | struct and modifies it  |
|            |          |                          |                          | without verifying the   |
|            |          |                          |                          | sender. On Sui,         |
|------------+----------+--------------------------+--------------------------+-------------------------|
| SUI-022    | Critical | Unprotected Shared       | hydra_vault::add_whiteli | Function takes a        |
|            |          | Object Mutation          | st                       | mutable reference to a  |
|            |          |                          |                          | struct and modifies it  |
|            |          |                          |                          | without verifying the   |
|            |          |                          |                          | sender. On Sui,         |
|------------+----------+--------------------------+--------------------------+-------------------------|
| SUI-022    | Critical | Unprotected Shared       | hydra_vault::set_pause   | Function takes a        |
|            |          | Object Mutation          |                          | mutable reference to a  |
|            |          |                          |                          | struct and modifies it  |
|            |          |                          |                          | without verifying the   |
|            |          |                          |                          | sender. On Sui,         |
|------------+----------+--------------------------+--------------------------+-------------------------|
| SUI-022    | Critical | Unprotected Shared       | hydra_vault::bump_versio | Function takes a        |
|            |          | Object Mutation          | n                        | mutable reference to a  |
|            |          |                          |                          | struct and modifies it  |
|            |          |                          |                          | without verifying the   |
|            |          |                          |                          | sender. On Sui,         |
|------------+----------+--------------------------+--------------------------+-------------------------|
| SUI-022    | Critical | Unprotected Shared       | hydra_vault::touch_nonce | Function takes a        |
|            |          | Object Mutation          |                          | mutable reference to a  |
|            |          |                          |                          | struct and modifies it  |
|            |          |                          |                          | without verifying the   |
|            |          |                          |                          | sender. On Sui,         |
|------------+----------+--------------------------+--------------------------+-------------------------|
| SUI-022    | Critical | Unprotected Shared       | hydra_vault::halve       | Function takes a        |
|            |          | Object Mutation          |                          | mutable reference to a  |
|            |          |                          |                          | struct and modifies it  |
|            |          |                          |                          | without verifying the   |
|            |          |                          |                          | sender. On Sui,         |
|------------+----------+--------------------------+--------------------------+-------------------------|
| SUI-022    | Critical | Unprotected Shared       | hydra_vault::compress    | Function takes a        |
|            |          | Object Mutation          |                          | mutable reference to a  |
|            |          |                          |                          | struct and modifies it  |
|            |          |                          |                          | without verifying the   |
|            |          |                          |                          | sender. On Sui,         |
|------------+----------+--------------------------+--------------------------+-------------------------|
| SUI-022    | Critical | Unprotected Shared       | hydra_vault::admin_only  | Function takes a        |
|            |          | Object Mutation          |                          | mutable reference to a  |
|            |          |                          |                          | struct and modifies it  |
|            |          |                          |                          | without verifying the   |
|            |          |                          |                          | sender. On Sui,         |
|------------+----------+--------------------------+--------------------------+-------------------------|
| SUI-033    | Critical | Phantom Authorization    | hydra_vault::init        | Function 'admin_only'   |
|            |          | Parameter                |                          | has a capability        |
|            |          |                          |                          | parameter 'AdminCap'    |
|            |          |                          |                          | that is NEVER USED in   |
|            |          |                          |                          | the function body.      |
|------------+----------+--------------------------+--------------------------+-------------------------|
| EXT-AC-007 | Critical | Admin function without   | hydra_vault::emergency_w | Admin function          |
|            |          | capability               | ithdraw                  | 'emergency_withdraw'    |
|            |          |                          |                          | lacks capability check  |
|------------+----------+--------------------------+--------------------------+-------------------------|
| EXT-AC-007 | Critical | Admin function without   | hydra_vault::conditional | Admin function          |
|            |          | capability               | _drain                   | 'conditional_drain'     |
|            |          |                          |                          | lacks capability check  |
|------------+----------+--------------------------+--------------------------+-------------------------|
| FIN-004    | Critical | Liquidity drain risk in  | hydra_vault::withdraw    | Withdrawal function     |
|            |          | 'withdraw'               |                          | lacks limits allowing   |
|            |          |                          |                          | complete liquidity      |
|            |          |                          |                          | drain                   |
|------------+----------+--------------------------+--------------------------+-------------------------|
| FIN-004    | Critical | Liquidity drain risk in  | hydra_vault::withdraw_la | Withdrawal function     |
|            |          | 'withdraw_last'          | st                       | lacks limits allowing   |
|            |          |                          |                          | complete liquidity      |
|            |          |                          |                          | drain                   |
|------------+----------+--------------------------+--------------------------+-------------------------|
| FIN-004    | Critical | Liquidity drain risk in  | hydra_vault::emergency_w | Withdrawal function     |
|            |          | 'emergency_withdraw'     | ithdraw                  | lacks limits allowing   |
|            |          |                          |                          | complete liquidity      |
|            |          |                          |                          | drain                   |
|------------+----------+--------------------------+--------------------------+-------------------------|
| AC-CAP-001 | Critical | Unprotected Capability   | chimera_vault::mint_admi | Function 'mint_admin'   |
|            |          | Minting                  | n                        | allows anyone to mint a |
|            |          |                          |                          | capability object.      |
|            |          |                          |                          | Capabilities should be  |
|            |          |                          |                          | strictly pro            |
|------------+----------+--------------------------+--------------------------+-------------------------|
| ARITH-003  | Critical | Unchecked subtraction    | chimera_vault::redeem    | Subtraction without     |
|            |          | may underflow            |                          | underflow protection    |
|------------+----------+--------------------------+--------------------------+-------------------------|
| ARITH-003  | Critical | Unchecked subtraction    | chimera_vault::redeem    | Subtraction without     |
|            |          | may underflow            |                          | underflow protection    |
|------------+----------+--------------------------+--------------------------+-------------------------|
| ARITH-003  | Critical | Unchecked subtraction    | chimera_vault::claim     | Subtraction without     |
|            |          | may underflow            |                          | underflow protection    |
|------------+----------+--------------------------+--------------------------+-------------------------|
| SUI-030    | High     | Unbounded Table/Bag      | chimera_vault::init      | Function                |
|            |          | Storage                  |                          | 'register_claim' adds   |
|            |          |                          |                          | entries to a Table/Bag  |
|            |          |                          |                          | without an apparent     |
|            |          |                          |                          | size limit. This can    |
|            |          |                          |                          | lead                    |
|------------+----------+--------------------------+--------------------------+-------------------------|
| SUI-030    | High     | Unbounded Table/Bag      | chimera_vault::init      | Function 'spam_claims'  |
|            |          | Storage                  |                          | adds entries to a       |
|            |          |                          |                          | Table/Bag without an    |
|            |          |                          |                          | apparent size limit.    |
|            |          |                          |                          | This can lead to        |
|------------+----------+--------------------------+--------------------------+-------------------------|
| SUI-027    | High     | Capability Theater       | chimera_vault::init      | The capability struct   |
|            |          |                          |                          | 'AdminCap' exists but   |
|            |          |                          |                          | is never used for       |
|            |          |                          |                          | authentication in any   |
|            |          |                          |                          | sensitive functi        |
|------------+----------+--------------------------+--------------------------+-------------------------|
| SUI-024    | Critical | Fake Balance Accounting  | chimera_vault::init      | Struct 'vault' tracks a |
|            |          |                          |                          | balance using 'u64' but |
|            |          |                          |                          | does not hold any       |
|            |          |                          |                          | 'Coin<T>' or            |
|            |          |                          |                          | 'Balance<T>' objects.   |
|------------+----------+--------------------------+--------------------------+-------------------------|
| SUI-026    | Medium   | Zero-Amount Deposit      | chimera_vault::deposit   | Function 'deposit'      |
|            |          | State Poisoning          |                          | allows zero-amount      |
|            |          |                          |                          | deposits. This can lead |
|            |          |                          |                          | to state poisoning,     |
|            |          |                          |                          | unnecessary vector      |
|------------+----------+--------------------------+--------------------------+-------------------------|
| SUI-025    | High     | Pause Flag Illusion      | chimera_vault::init      | The field 'paused' is   |
|            |          |                          |                          | defined and likely      |
|            |          |                          |                          | settable, but its value |
|            |          |                          |                          | is never checked in any |
|            |          |                          |                          | conditional             |
|------------+----------+--------------------------+--------------------------+-------------------------|
| SUI-028    | Medium   | Internal Reference       | chimera_vault::inspect   | Public function         |
|            |          | Exposure                 |                          | 'inspect' returns a     |
|            |          |                          |                          | reference to a struct.  |
|            |          |                          |                          | This may leak internal  |
|            |          |                          |                          | protocol state or       |
|------------+----------+--------------------------+--------------------------+-------------------------|
| ARITH-005  | Critical | Division without zero    | chimera_vault::deposit   | Division may cause      |
|            |          | check                    |                          | panic if divisor is     |
|            |          |                          |                          | zero                    |
|------------+----------+--------------------------+--------------------------+-------------------------|
| SUI-022    | Critical | Unprotected Shared       | chimera_vault::deposit   | Function takes a        |
|            |          | Object Mutation          |                          | mutable reference to a  |
|            |          |                          |                          | struct and modifies it  |
|            |          |                          |                          | without verifying the   |
|            |          |                          |                          | sender. On Sui,         |
|------------+----------+--------------------------+--------------------------+-------------------------|
| SUI-022    | Critical | Unprotected Shared       | chimera_vault::set_share | Function takes a        |
|            |          | Object Mutation          | _price                   | mutable reference to a  |
|            |          |                          |                          | struct and modifies it  |
|            |          |                          |                          | without verifying the   |
|            |          |                          |                          | sender. On Sui,         |
|------------+----------+--------------------------+--------------------------+-------------------------|
| SUI-022    | Critical | Unprotected Shared       | chimera_vault::redeem    | Function takes a        |
|            |          | Object Mutation          |                          | mutable reference to a  |
|            |          |                          |                          | struct and modifies it  |
|            |          |                          |                          | without verifying the   |
|            |          |                          |                          | sender. On Sui,         |
|------------+----------+--------------------------+--------------------------+-------------------------|
| SUI-022    | Critical | Unprotected Shared       | chimera_vault::emergency | Function takes a        |
|            |          | Object Mutation          | _withdraw                | mutable reference to a  |
|            |          |                          |                          | struct and modifies it  |
|            |          |                          |                          | without verifying the   |
|            |          |                          |                          | sender. On Sui,         |
|------------+----------+--------------------------+--------------------------+-------------------------|
| SUI-022    | Critical | Unprotected Shared       | chimera_vault::register_ | Function takes a        |
|            |          | Object Mutation          | claim                    | mutable reference to a  |
|            |          |                          |                          | struct and modifies it  |
|            |          |                          |                          | without verifying the   |
|            |          |                          |                          | sender. On Sui,         |
|------------+----------+--------------------------+--------------------------+-------------------------|
| SUI-022    | Critical | Unprotected Shared       | chimera_vault::claim     | Function takes a        |
|            |          | Object Mutation          |                          | mutable reference to a  |
|            |          |                          |                          | struct and modifies it  |
|            |          |                          |                          | without verifying the   |
|            |          |                          |                          | sender. On Sui,         |
|------------+----------+--------------------------+--------------------------+-------------------------|
| SUI-022    | Critical | Unprotected Shared       | chimera_vault::set_contr | Function takes a        |
|            |          | Object Mutation          | oller                    | mutable reference to a  |
|            |          |                          |                          | struct and modifies it  |
|            |          |                          |                          | without verifying the   |
|            |          |                          |                          | sender. On Sui,         |
|------------+----------+--------------------------+--------------------------+-------------------------|
| SUI-022    | Critical | Unprotected Shared       | chimera_vault::set_owner | Function takes a        |
|            |          | Object Mutation          |                          | mutable reference to a  |
|            |          |                          |                          | struct and modifies it  |
|            |          |                          |                          | without verifying the   |
|            |          |                          |                          | sender. On Sui,         |
|------------+----------+--------------------------+--------------------------+-------------------------|
| SUI-022    | Critical | Unprotected Shared       | chimera_vault::admin_act | Function takes a        |
|            |          | Object Mutation          | ion                      | mutable reference to a  |
|            |          |                          |                          | struct and modifies it  |
|            |          |                          |                          | without verifying the   |
|            |          |                          |                          | sender. On Sui,         |
|------------+----------+--------------------------+--------------------------+-------------------------|
| SUI-022    | Critical | Unprotected Shared       | chimera_vault::decay     | Function takes a        |
|            |          | Object Mutation          |                          | mutable reference to a  |
|            |          |                          |                          | struct and modifies it  |
|            |          |                          |                          | without verifying the   |
|            |          |                          |                          | sender. On Sui,         |
|------------+----------+--------------------------+--------------------------+-------------------------|
| SUI-022    | Critical | Unprotected Shared       | chimera_vault::smooth    | Function takes a        |
|            |          | Object Mutation          |                          | mutable reference to a  |
|            |          |                          |                          | struct and modifies it  |
|            |          |                          |                          | without verifying the   |
|            |          |                          |                          | sender. On Sui,         |
|------------+----------+--------------------------+--------------------------+-------------------------|
| SUI-033    | Critical | Phantom Authorization    | chimera_vault::init      | Function 'admin_action' |
|            |          | Parameter                |                          | has a capability        |
|            |          |                          |                          | parameter 'AdminCap'    |
|            |          |                          |                          | that is NEVER USED in   |
|            |          |                          |                          | the function bod        |
|------------+----------+--------------------------+--------------------------+-------------------------|
| ARITH-002  | Critical | Unchecked multiplication | chimera_vault::redeem    | Multiplication without  |
|            |          | may overflow             |                          | overflow checks         |
|------------+----------+--------------------------+--------------------------+-------------------------|
| EXT-AC-007 | Critical | Admin function without   | chimera_vault::emergency | Admin function          |
|            |          | capability               | _withdraw                | 'emergency_withdraw'    |
|            |          |                          |                          | lacks capability check  |
|------------+----------+--------------------------+--------------------------+-------------------------|
| FIN-004    | Critical | Liquidity drain risk in  | chimera_vault::emergency | Withdrawal function     |
|            |          | 'emergency_withdraw'     | _withdraw                | lacks limits allowing   |
|            |          |                          |                          | complete liquidity      |
|            |          |                          |                          | drain                   |
|------------+----------+--------------------------+--------------------------+-------------------------|
| SUI-024    | Critical | Fake Balance Accounting  | vulnerable_vault::init_v | Struct 'vault' tracks a |
|            |          |                          | ault                     | balance using 'u64' but |
|            |          |                          |                          | does not hold any       |
|            |          |                          |                          | 'Coin<T>' or            |
|            |          |                          |                          | 'Balance<T>' objects.   |
|------------+----------+--------------------------+--------------------------+-------------------------|
| SUI-026    | Medium   | Zero-Amount Deposit      | vulnerable_vault::deposi | Function 'deposit'      |
|            |          | State Poisoning          | t                        | allows zero-amount      |
|            |          |                          |                          | deposits. This can lead |
|            |          |                          |                          | to state poisoning,     |
|            |          |                          |                          | unnecessary vector      |
|------------+----------+--------------------------+--------------------------+-------------------------|
| SUI-023    | High     | Meaningless Assertion    | vulnerable_vault::withdr | Detected 'assert!(x >=  |
|            |          |                          | aw                       | 0)' or similar on an    |
|            |          |                          |                          | unsigned integer (u64). |
|            |          |                          |                          | This check is always    |
|            |          |                          |                          | true and pr             |
|------------+----------+--------------------------+--------------------------+-------------------------|
| SUI-022    | Critical | Unprotected Shared       | vulnerable_vault::deposi | Function takes a        |
|            |          | Object Mutation          | t                        | mutable reference to a  |
|            |          |                          |                          | struct and modifies it  |
|            |          |                          |                          | without verifying the   |
|            |          |                          |                          | sender. On Sui,         |
|------------+----------+--------------------------+--------------------------+-------------------------|
| SUI-022    | Critical | Unprotected Shared       | vulnerable_vault::admin_ | Function takes a        |
|            |          | Object Mutation          | drain                    | mutable reference to a  |
|            |          |                          |                          | struct and modifies it  |
|            |          |                          |                          | without verifying the   |
|            |          |                          |                          | sender. On Sui,         |
|------------+----------+--------------------------+--------------------------+-------------------------|
| SUI-021    | Critical | Unrestricted Shared      | vulnerable_vault::init_v | Entry function shares   |
|            |          | Object Initialization    | ault                     | an object without any   |
|            |          |                          |                          | visible access control  |
|            |          |                          |                          | or capability check.    |
|            |          |                          |                          | This may all            |
|------------+----------+--------------------------+--------------------------+-------------------------|
| EXT-AC-007 | Critical | Admin function without   | vulnerable_vault::admin_ | Admin function          |
|            |          | capability               | drain                    | 'admin_drain' lacks     |
|            |          |                          |                          | capability check        |
|------------+----------+--------------------------+--------------------------+-------------------------|
| FIN-004    | Critical | Liquidity drain risk in  | vulnerable_vault::withdr | Withdrawal function     |
|            |          | 'withdraw'               | aw                       | lacks limits allowing   |
|            |          |                          |                          | complete liquidity      |
|            |          |                          |                          | drain                   |
+------------+----------+--------------------------+--------------------------+-------------------------+

Total issues found: 112

⚠️ 82 critical and 18 high severity issues found!
```