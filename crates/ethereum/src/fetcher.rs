//! Block and transaction fetcher for Ethereum.

use crate::{EthereumError, Result};
use ethers::{
    providers::{Http, Middleware, Provider},
    types::{Block, Transaction, H256, U64},
};
use serde::{Deserialize, Serialize};

/// Ethereum block fetcher with state access.
pub struct BlockFetcher {
    provider: Provider<Http>,
}

impl BlockFetcher {
    /// Create a new block fetcher with the given RPC URL.
    pub async fn new(rpc_url: &str) -> Result<Self> {
        let provider = Provider::<Http>::try_from(rpc_url)
            .map_err(|e| EthereumError::BlockFetchError(format!("Invalid RPC URL: {}", e)))?;
        Ok(Self { provider })
    }

    /// Get the RPC provider reference.
    pub fn provider(&self) -> &Provider<Http> {
        &self.provider
    }

    /// Fetch a block by number with all transactions.
    pub async fn fetch_block(&self, block_number: u64) -> Result<BlockData> {
        let block = self
            .provider
            .get_block_with_txs(block_number)
            .await?
            .ok_or_else(|| {
                EthereumError::BlockFetchError(format!("Block {} not found", block_number))
            })?;

        Ok(BlockData::from_ethers_block(block))
    }

    /// Fetch the latest block.
    pub async fn fetch_latest_block(&self) -> Result<BlockData> {
        let block_number = self.provider.get_block_number().await?;
        self.fetch_block(block_number.as_u64()).await
    }

    /// Fetch a range of blocks.
    pub async fn fetch_block_range(&self, from: u64, to: u64) -> Result<Vec<BlockData>> {
        let mut blocks = Vec::new();
        for block_num in from..=to {
            let block = self.fetch_block(block_num).await?;
            blocks.push(block);
        }
        Ok(blocks)
    }

    /// Fetch a specific transaction.
    pub async fn fetch_transaction(&self, tx_hash: H256) -> Result<Transaction> {
        self.provider
            .get_transaction(tx_hash)
            .await?
            .ok_or_else(|| {
                EthereumError::BlockFetchError(format!("Transaction {:?} not found", tx_hash))
            })
    }

    // =========================================================================
    // ACCOUNT STATE FETCHING
    // =========================================================================

    /// Fetch account balance at a specific block.
    pub async fn get_balance(
        &self,
        address: ethers::types::Address,
        block: Option<u64>,
    ) -> Result<ethers::types::U256> {
        let block_id = block.map(|b| {
            ethers::types::BlockId::Number(ethers::types::BlockNumber::Number(U64::from(b)))
        });
        Ok(self.provider.get_balance(address, block_id).await?)
    }

    /// Fetch account nonce at a specific block.
    pub async fn get_nonce(
        &self,
        address: ethers::types::Address,
        block: Option<u64>,
    ) -> Result<u64> {
        let block_id = block.map(|b| {
            ethers::types::BlockId::Number(ethers::types::BlockNumber::Number(U64::from(b)))
        });
        Ok(self
            .provider
            .get_transaction_count(address, block_id)
            .await?
            .as_u64())
    }

    /// Fetch contract code at a specific block.
    pub async fn get_code(
        &self,
        address: ethers::types::Address,
        block: Option<u64>,
    ) -> Result<Vec<u8>> {
        let block_id = block.map(|b| {
            ethers::types::BlockId::Number(ethers::types::BlockNumber::Number(U64::from(b)))
        });
        Ok(self.provider.get_code(address, block_id).await?.to_vec())
    }

    /// Fetch storage slot value at a specific block.
    pub async fn get_storage_at(
        &self,
        address: ethers::types::Address,
        slot: H256,
        block: Option<u64>,
    ) -> Result<H256> {
        let block_id = block.map(|b| {
            ethers::types::BlockId::Number(ethers::types::BlockNumber::Number(U64::from(b)))
        });
        Ok(self
            .provider
            .get_storage_at(address, slot, block_id)
            .await?)
    }
}

/// Simplified block data for proving.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockData {
    pub number: u64,
    pub hash: H256,
    pub parent_hash: H256,
    pub timestamp: u64,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub transactions: Vec<TransactionData>,
}

impl BlockData {
    fn from_ethers_block(block: Block<Transaction>) -> Self {
        Self {
            number: block.number.unwrap_or_default().as_u64(),
            hash: block.hash.unwrap_or_default(),
            parent_hash: block.parent_hash,
            timestamp: block.timestamp.as_u64(),
            gas_limit: block.gas_limit.as_u64(),
            gas_used: block.gas_used.as_u64(),
            transactions: block
                .transactions
                .into_iter()
                .map(TransactionData::from_ethers_tx)
                .collect(),
        }
    }
}

/// Simplified transaction data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionData {
    pub hash: H256,
    pub from: ethers::types::Address,
    pub to: Option<ethers::types::Address>,
    pub value: ethers::types::U256,
    pub gas: u64,
    pub gas_price: Option<ethers::types::U256>,
    pub input: Vec<u8>,
    pub nonce: u64,
}

impl TransactionData {
    fn from_ethers_tx(tx: Transaction) -> Self {
        Self {
            hash: tx.hash,
            from: tx.from,
            to: tx.to,
            value: tx.value,
            gas: tx.gas.as_u64(),
            gas_price: tx.gas_price,
            input: tx.input.to_vec(),
            nonce: tx.nonce.as_u64(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore] // Requires RPC connection
    async fn test_fetch_block() {
        let fetcher = BlockFetcher::new("http://localhost:8545")
            .await
            .expect("Failed to create fetcher");

        let block = fetcher.fetch_block(1).await.expect("Failed to fetch block");

        assert_eq!(block.number, 1);
    }
}
