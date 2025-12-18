use crate::fetcher::TransactionData;
use crate::transaction::TransactionResult;
use ethers::types::{Address as EthersAddress, H256 as EthersH256, U256 as EthersU256};
use revm::{
    db::{CacheDB, EmptyDB},
    primitives::{
        AccountInfo, Address as RevmAddress, Bytes, CreateScheme, ExecutionResult, Output,
        TransactTo, U256 as RevmU256,
    },
    EVM,
};

/// Convert Ethers Address to Revm Address
fn to_revm_address(addr: EthersAddress) -> RevmAddress {
    RevmAddress::from_slice(addr.as_bytes())
}

/// Convert Ethers U256 to Revm U256
fn to_revm_u256(val: EthersU256) -> RevmU256 {
    let mut bytes = [0u8; 32];
    val.to_big_endian(&mut bytes);
    RevmU256::from_be_bytes(bytes)
}

/// Execute a transaction using Revm
pub fn execute_tx(tx: &TransactionData) -> anyhow::Result<TransactionResult> {
    // Initialize EVM with empty DB
    // In a real scenario, we would load state from a provider or disk
    let mut db = CacheDB::new(EmptyDB::default());

    // Calculate required balance: gas_limit * gas_price + value + buffer
    // For EIP-1559, gas_price might be max_fee_per_gas which can be very high
    let gas_cost = if let Some(price) = tx.gas_price {
        to_revm_u256(price) * RevmU256::from(tx.gas)
    } else {
        RevmU256::from(tx.gas) * RevmU256::from(100_000_000_000u64) // 100 gwei fallback
    };
    let tx_value = to_revm_u256(tx.value);
    // Add extra buffer (100 ETH) to ensure no balance issues
    let required_balance = gas_cost + tx_value + RevmU256::from(100_000_000_000_000_000_000u128);

    // Setup sender account with sufficient balance to pay for gas + value
    let sender = to_revm_address(tx.from);
    let sender_info = AccountInfo {
        balance: required_balance,
        nonce: tx.nonce,
        code_hash: RevmU256::ZERO.into(), // Empty code hash
        code: None,
    };
    db.insert_account_info(sender, sender_info);

    let mut evm = EVM::new();
    evm.database(db);

    // Configure transaction
    evm.env.tx.caller = sender;
    evm.env.tx.transact_to = if let Some(to) = tx.to {
        TransactTo::Call(to_revm_address(to))
    } else {
        TransactTo::Create(CreateScheme::Create)
    };
    evm.env.tx.data = Bytes::from(tx.input.clone());
    evm.env.tx.value = to_revm_u256(tx.value);
    evm.env.tx.gas_limit = tx.gas;
    if let Some(price) = tx.gas_price {
        evm.env.tx.gas_price = to_revm_u256(price);
    }

    // Execute
    let result_and_state = evm.transact_commit()?;
    let result = result_and_state;

    // Process result
    let (success, return_data, gas_used) = match result {
        ExecutionResult::Success {
            output, gas_used, ..
        } => {
            let data = match output {
                Output::Call(bytes) => bytes.to_vec(),
                Output::Create(bytes, _) => bytes.to_vec(),
            };
            (true, data, gas_used)
        }
        ExecutionResult::Revert { output, gas_used } => (false, output.to_vec(), gas_used),
        ExecutionResult::Halt {
            reason: _,
            gas_used,
        } => (false, vec![], gas_used),
    };

    // Collect state changes (simplified)
    // In a real implementation, we would inspect the State returned by transact()
    // But transact_commit() consumes it.
    // For now, we'll return an empty list of state changes as we are using EmptyDB
    let state_changes = Vec::new();

    Ok(TransactionResult {
        hash: tx.hash,
        gas_used,
        success,
        return_data,
        state_changes,
    })
}

/// Execute a transaction using Revm with RPC-backed state.
///
/// This fetches real account balances, nonces, and contract code from the RPC.
pub fn execute_tx_with_rpc(
    tx: &TransactionData,
    rpc_url: &str,
    block_number: Option<u64>,
) -> anyhow::Result<TransactionResult> {
    use crate::rpc_db::RpcDb;
    use revm::db::CacheDB;

    // Create RPC-backed database
    let rpc_db = RpcDb::from_rpc_url(rpc_url, block_number)
        .map_err(|e| anyhow::anyhow!("RPC DB error: {}", e))?;

    // Wrap in CacheDB for better performance
    let mut db = CacheDB::new(rpc_db);

    // For contract calls, we also need to ensure the sender has enough balance
    // The RPC will fetch the real balance, but we might need to override it
    // for simulation purposes
    let sender = to_revm_address(tx.from);

    // Calculate required balance for this tx
    let gas_cost = if let Some(price) = tx.gas_price {
        to_revm_u256(price) * RevmU256::from(tx.gas)
    } else {
        RevmU256::from(tx.gas) * RevmU256::from(100_000_000_000u64)
    };
    let tx_value = to_revm_u256(tx.value);
    let required = gas_cost + tx_value;

    // Insert sender with sufficient balance if needed
    // This is a simulation - we assume sender can pay
    let sender_info = AccountInfo {
        balance: required + RevmU256::from(100_000_000_000_000_000_000u128),
        nonce: tx.nonce,
        code_hash: RevmU256::ZERO.into(),
        code: None,
    };
    db.insert_account_info(sender, sender_info);

    let mut evm = EVM::new();
    evm.database(db);

    // Configure transaction
    evm.env.tx.caller = sender;
    evm.env.tx.transact_to = if let Some(to) = tx.to {
        TransactTo::Call(to_revm_address(to))
    } else {
        TransactTo::Create(CreateScheme::Create)
    };
    evm.env.tx.data = Bytes::from(tx.input.clone());
    evm.env.tx.value = to_revm_u256(tx.value);
    evm.env.tx.gas_limit = tx.gas;
    if let Some(price) = tx.gas_price {
        evm.env.tx.gas_price = to_revm_u256(price);
    }

    // Execute
    let result = evm.transact_commit()?;

    // Process result
    let (success, return_data, gas_used) = match result {
        ExecutionResult::Success {
            output, gas_used, ..
        } => {
            let data = match output {
                Output::Call(bytes) => bytes.to_vec(),
                Output::Create(bytes, _) => bytes.to_vec(),
            };
            (true, data, gas_used)
        }
        ExecutionResult::Revert { output, gas_used } => (false, output.to_vec(), gas_used),
        ExecutionResult::Halt {
            reason: _,
            gas_used,
        } => (false, vec![], gas_used),
    };

    let state_changes = Vec::new();

    Ok(TransactionResult {
        hash: tx.hash,
        gas_used,
        success,
        return_data,
        state_changes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethers::types::U256;

    #[test]
    fn test_execute_simple_transfer() {
        let from = EthersAddress::random();
        let to = EthersAddress::random();
        let value = U256::from(1000);

        let tx = TransactionData {
            hash: EthersH256::random(),
            from,
            to: Some(to),
            value,
            gas: 21000,
            gas_price: Some(U256::from(10)),
            input: vec![],
            nonce: 0,
        };

        let result = execute_tx(&tx).expect("Execution failed");

        assert!(result.success);
        assert_eq!(result.gas_used, 21000);
    }
}
