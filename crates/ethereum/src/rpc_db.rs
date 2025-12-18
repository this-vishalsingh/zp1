//! RPC-backed database for REVM.
//!
//! This module provides an RPC-backed database implementation for REVM,
//! allowing EVM execution with real blockchain state.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::runtime::Runtime;

use ethers::{
    providers::{Http, Middleware, Provider},
    types::{Address as EthersAddress, BlockId, BlockNumber, H256, U256 as EthersU256},
};
use revm::{
    db::Database,
    primitives::{
        AccountInfo, Address as RevmAddress, Bytecode, B256, KECCAK_EMPTY, U256 as RevmU256,
    },
};

/// Convert Ethers Address to Revm Address
fn ethers_to_revm_address(addr: EthersAddress) -> RevmAddress {
    RevmAddress::from_slice(addr.as_bytes())
}

/// Convert Revm Address to Ethers Address
fn revm_to_ethers_address(addr: RevmAddress) -> EthersAddress {
    EthersAddress::from_slice(addr.as_slice())
}

/// Convert Ethers U256 to Revm U256
fn ethers_to_revm_u256(val: EthersU256) -> RevmU256 {
    let mut bytes = [0u8; 32];
    val.to_big_endian(&mut bytes);
    RevmU256::from_be_bytes(bytes)
}

/// Convert H256 to B256
fn h256_to_b256(h: H256) -> B256 {
    B256::from_slice(h.as_bytes())
}

/// Convert B256 to H256
fn b256_to_h256(b: B256) -> H256 {
    H256::from_slice(b.as_slice())
}

/// RPC-backed database for REVM.
///
/// Fetches account state and storage from an Ethereum RPC endpoint.
/// Uses a cache to minimize RPC calls.
pub struct RpcDb {
    provider: Arc<Provider<Http>>,
    runtime: Arc<Runtime>,
    block_number: Option<u64>,
    // Caches
    account_cache: HashMap<RevmAddress, AccountInfo>,
    code_cache: HashMap<RevmAddress, Bytecode>,
    storage_cache: HashMap<(RevmAddress, RevmU256), RevmU256>,
}

impl RpcDb {
    /// Create a new RPC database.
    pub fn new(
        provider: Arc<Provider<Http>>,
        runtime: Arc<Runtime>,
        block_number: Option<u64>,
    ) -> Self {
        Self {
            provider,
            runtime,
            block_number,
            account_cache: HashMap::new(),
            code_cache: HashMap::new(),
            storage_cache: HashMap::new(),
        }
    }

    /// Create from RPC URL.
    pub fn from_rpc_url(rpc_url: &str, block_number: Option<u64>) -> Result<Self, String> {
        let provider =
            Provider::<Http>::try_from(rpc_url).map_err(|e| format!("Invalid RPC URL: {}", e))?;
        let runtime = Runtime::new().map_err(|e| format!("Failed to create runtime: {}", e))?;
        Ok(Self::new(
            Arc::new(provider),
            Arc::new(runtime),
            block_number,
        ))
    }

    /// Get block ID for queries.
    fn block_id(&self) -> Option<BlockId> {
        self.block_number
            .map(|n| BlockId::Number(BlockNumber::Number(n.into())))
    }

    /// Fetch account info from RPC.
    fn fetch_account(&self, address: RevmAddress) -> Result<AccountInfo, String> {
        let ethers_addr = revm_to_ethers_address(address);
        let block_id = self.block_id();

        self.runtime.block_on(async {
            // Fetch balance
            let balance = self
                .provider
                .get_balance(ethers_addr, block_id)
                .await
                .map_err(|e| format!("Failed to fetch balance: {}", e))?;

            // Fetch nonce
            let nonce = self
                .provider
                .get_transaction_count(ethers_addr, block_id)
                .await
                .map_err(|e| format!("Failed to fetch nonce: {}", e))?;

            // Fetch code
            let code = self
                .provider
                .get_code(ethers_addr, block_id)
                .await
                .map_err(|e| format!("Failed to fetch code: {}", e))?;

            let code_bytes = code.to_vec();
            let code_hash = if code_bytes.is_empty() {
                KECCAK_EMPTY
            } else {
                // Use revm's keccak256 utility
                revm::primitives::keccak256(&code_bytes)
            };

            Ok(AccountInfo {
                balance: ethers_to_revm_u256(balance),
                nonce: nonce.as_u64(),
                code_hash,
                code: if code_bytes.is_empty() {
                    None
                } else {
                    Some(Bytecode::new_raw(code_bytes.into()))
                },
            })
        })
    }

    /// Fetch storage slot from RPC.
    fn fetch_storage(&self, address: RevmAddress, slot: RevmU256) -> Result<RevmU256, String> {
        let ethers_addr = revm_to_ethers_address(address);
        let block_id = self.block_id();

        // Convert slot to H256
        let slot_bytes = slot.to_be_bytes::<32>();
        let slot_h256 = H256::from_slice(&slot_bytes);

        self.runtime.block_on(async {
            let value = self
                .provider
                .get_storage_at(ethers_addr, slot_h256, block_id)
                .await
                .map_err(|e| format!("Failed to fetch storage: {}", e))?;

            let mut bytes = [0u8; 32];
            value
                .to_fixed_bytes()
                .iter()
                .enumerate()
                .for_each(|(i, b)| bytes[i] = *b);
            Ok(RevmU256::from_be_bytes(bytes))
        })
    }
}

impl Database for RpcDb {
    type Error = String;

    fn basic(&mut self, address: RevmAddress) -> Result<Option<AccountInfo>, Self::Error> {
        // Check cache first
        if let Some(info) = self.account_cache.get(&address) {
            return Ok(Some(info.clone()));
        }

        // Fetch from RPC
        let info = self.fetch_account(address)?;
        self.account_cache.insert(address, info.clone());
        Ok(Some(info))
    }

    fn code_by_hash(&mut self, _code_hash: B256) -> Result<Bytecode, Self::Error> {
        // This is tricky - we'd need to look up code by hash
        // For now, return empty bytecode (code is already in AccountInfo)
        Ok(Bytecode::new())
    }

    fn storage(&mut self, address: RevmAddress, slot: RevmU256) -> Result<RevmU256, Self::Error> {
        let key = (address, slot);

        // Check cache first
        if let Some(value) = self.storage_cache.get(&key) {
            return Ok(*value);
        }

        // Fetch from RPC
        let value = self.fetch_storage(address, slot)?;
        self.storage_cache.insert(key, value);
        Ok(value)
    }

    fn block_hash(&mut self, number: RevmU256) -> Result<B256, Self::Error> {
        let block_num: u64 = number.try_into().unwrap_or(0);
        self.runtime.block_on(async {
            let block = self
                .provider
                .get_block(block_num)
                .await
                .map_err(|e| format!("Failed to fetch block: {}", e))?
                .ok_or_else(|| format!("Block {} not found", block_num))?;

            Ok(h256_to_b256(block.hash.unwrap_or_default()))
        })
    }
}

impl revm::db::DatabaseRef for RpcDb {
    type Error = String;

    fn basic(&self, address: RevmAddress) -> Result<Option<AccountInfo>, Self::Error> {
        // Check cache first
        if let Some(info) = self.account_cache.get(&address) {
            return Ok(Some(info.clone()));
        }

        // Fetch from RPC
        self.fetch_account(address).map(Some)
    }

    fn code_by_hash(&self, _code_hash: B256) -> Result<Bytecode, Self::Error> {
        Ok(Bytecode::new())
    }

    fn storage(&self, address: RevmAddress, slot: RevmU256) -> Result<RevmU256, Self::Error> {
        let key = (address, slot);
        if let Some(value) = self.storage_cache.get(&key) {
            return Ok(*value);
        }
        self.fetch_storage(address, slot)
    }

    fn block_hash(&self, number: RevmU256) -> Result<B256, Self::Error> {
        let block_num: u64 = number.try_into().unwrap_or(0);
        self.runtime.block_on(async {
            let block = self
                .provider
                .get_block(block_num)
                .await
                .map_err(|e| format!("Failed to fetch block: {}", e))?
                .ok_or_else(|| format!("Block {} not found", block_num))?;

            Ok(h256_to_b256(block.hash.unwrap_or_default()))
        })
    }
}

/// Statistics about RPC database usage.
#[derive(Debug, Default, Clone)]
pub struct RpcDbStats {
    pub accounts_fetched: usize,
    pub storage_slots_fetched: usize,
    pub blocks_fetched: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_conversion() {
        let ethers_addr = EthersAddress::random();
        let revm_addr = ethers_to_revm_address(ethers_addr);
        let back = revm_to_ethers_address(revm_addr);
        assert_eq!(ethers_addr, back);
    }

    #[test]
    fn test_u256_conversion() {
        let val = EthersU256::from(12345678u64);
        let revm_val = ethers_to_revm_u256(val);
        assert_eq!(revm_val, RevmU256::from(12345678u64));
    }
}
