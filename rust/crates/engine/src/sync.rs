use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Result;
use prost::Message;
use tokio::sync::Mutex as TokioMutex;

use zcash_client_backend::data_api::chain::error::Error as ChainError;
use zcash_client_backend::data_api::chain::{scan_cached_blocks, BlockSource, CommitmentTreeRoot};
use zcash_client_backend::data_api::scanning::ScanPriority;
use zcash_client_backend::data_api::wallet::ConfirmationsPolicy;
use zcash_client_backend::data_api::{WalletCommitmentTrees, WalletRead, WalletWrite};
use zcash_client_backend::proto::compact_formats::CompactBlock;
use zcash_client_backend::proto::service::{
    compact_tx_streamer_client::CompactTxStreamerClient, BlockId, BlockRange, ChainSpec,
    GetAddressUtxosArg, GetSubtreeRootsArg, ShieldedProtocol, TreeState,
};
use zcash_client_backend::wallet::WalletTransparentOutput;
use zcash_client_sqlite::WalletDb;
use zcash_keys::encoding::AddressCodec as _;
use zcash_protocol::consensus::{BlockHeight, Network};
use zcash_protocol::value::Zatoshis;
use zcash_transparent::address::Script;
use zcash_transparent::bundle::{OutPoint, TxOut};

use zcash_primitives::block::BlockHash;
use zcash_primitives::merkle_tree::HashSer;

use super::wallet::connect_lwd;
use super::{open_wallet_db, open_cipher_conn, ENGINE};

// ---------------------------------------------------------------------------
// Sync state
// ---------------------------------------------------------------------------

static SYNC_RUNNING: AtomicBool = AtomicBool::new(false);
static SYNC_CANCEL: AtomicBool = AtomicBool::new(false);
/// Set when a sync pass ends with the wallet reporting nothing left to scan
/// up to the chain tip fetched in that same pass (see `caught_up`).
static SYNC_CAUGHT_UP: AtomicBool = AtomicBool::new(false);

/// How far below the failing block the wallet is rewound when a chain
/// continuity error (reorg) is detected — the same margin upstream
/// `zcash_client_backend::sync` uses.
const REORG_REWIND_BLOCKS: u32 = 10;
/// Pause after a rewind before rescanning, doubled on each consecutive
/// rewind up to the maximum, so that a server which keeps serving an
/// inconsistent chain cannot spin the loop.
const REORG_BACKOFF_SECS: u64 = 5;
const REORG_BACKOFF_MAX_SECS: u64 = 60;

lazy_static::lazy_static! {
    static ref SYNC_PROGRESS: TokioMutex<SyncProgressInfo> =
        TokioMutex::new(SyncProgressInfo::default());

    static ref INACTIVE_WALLETS: TokioMutex<Vec<InactiveWallet>> =
        TokioMutex::new(Vec::new());
}

#[derive(Default, Clone, Debug, serde::Serialize)]
pub struct SyncProgressInfo {
    pub synced_height: u32,
    pub latest_height: u32,
    pub is_syncing: bool,
    pub connection_error: Option<String>,
    pub scanning_up_to: u32,
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub(crate) struct InactiveWallet {
    pub db_data_path: PathBuf,
    pub db_cache_path: PathBuf,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

pub async fn start() -> Result<()> {
    if SYNC_RUNNING.load(Ordering::SeqCst) {
        return Err(anyhow::anyhow!("Sync already running"));
    }

    let engine_guard = ENGINE.lock().await;
    let engine = engine_guard
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Engine not initialized"))?;

    let db_data_path = engine.db_data_path.clone();
    let db_cache_path = engine.db_cache_path.clone();
    let params = engine.params;
    let server_url = engine.server_url.clone();
    let db_cipher_key = engine.db_cipher_key.clone();
    drop(engine_guard);

    SYNC_RUNNING.store(true, Ordering::SeqCst);
    SYNC_CANCEL.store(false, Ordering::SeqCst);
    SYNC_CAUGHT_UP.store(false, Ordering::SeqCst);
    {
        let mut p = SYNC_PROGRESS.lock().await;
        p.is_syncing = true;
        p.synced_height = 0;
        p.latest_height = 0;
        p.connection_error = None;
        p.scanning_up_to = 0;
    }

    tokio::spawn(async move {
        match sync_loop_with_retry(
            &db_data_path,
            &db_cache_path,
            params,
            &server_url,
            &db_cipher_key,
        )
        .await
        {
            Ok(()) => tracing::info!("[engine sync] completed successfully"),
            Err(e) => tracing::error!("[engine sync] error: {:?}", e),
        }
        SYNC_RUNNING.store(false, Ordering::SeqCst);
        {
            let mut p = SYNC_PROGRESS.lock().await;
            p.is_syncing = false;
        }
    });

    Ok(())
}

pub async fn stop() {
    SYNC_CANCEL.store(true, Ordering::SeqCst);
    for _ in 0..100 {
        if !SYNC_RUNNING.load(Ordering::SeqCst) {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    SYNC_RUNNING.store(false, Ordering::SeqCst);
}

pub fn is_running() -> bool {
    SYNC_RUNNING.load(Ordering::SeqCst)
}

/// `true` once the running sync has completed a pass in which the wallet had
/// no range left to scan — nothing unscanned anywhere between the account
/// birthday and the chain tip fetched at the start of that pass. This is the
/// wallet's own scan queue (`suggest_scan_ranges`) speaking, not a
/// comparison of the last scanned height with the tip (which can be true
/// while older ranges are still pending, because the tip range is scanned
/// first). Reset to `false` by `start()` and whenever a later pass finds
/// work again (new blocks, a reorg rewind).
pub fn caught_up() -> bool {
    SYNC_CAUGHT_UP.load(Ordering::SeqCst)
}

pub async fn get_progress() -> SyncProgressInfo {
    SYNC_PROGRESS.lock().await.clone()
}

pub async fn register_inactive_wallet(data_dir: &str) {
    let (db_data_path, db_cache_path) = super::db_paths(data_dir);
    let mut wallets = INACTIVE_WALLETS.lock().await;
    if !wallets.iter().any(|w| w.db_data_path == db_data_path) {
        wallets.push(InactiveWallet {
            db_data_path,
            db_cache_path,
        });
    }
}

pub async fn unregister_inactive_wallet(data_dir: &str) {
    let (db_data_path, _) = super::db_paths(data_dir);
    let mut wallets = INACTIVE_WALLETS.lock().await;
    wallets.retain(|w| w.db_data_path != db_data_path);
}

pub async fn clear_inactive_wallets() {
    let mut wallets = INACTIVE_WALLETS.lock().await;
    wallets.clear();
}

// ---------------------------------------------------------------------------
// Block cache — simple SQLite store implementing BlockSource
// ---------------------------------------------------------------------------

struct BlockCache {
    conn: rusqlite::Connection,
}

#[derive(Debug)]
pub struct BlockCacheError(String);

impl std::fmt::Display for BlockCacheError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "BlockCacheError: {}", self.0)
    }
}

impl std::error::Error for BlockCacheError {}

impl From<rusqlite::Error> for BlockCacheError {
    fn from(e: rusqlite::Error) -> Self {
        BlockCacheError(e.to_string())
    }
}

impl BlockCache {
    fn open(path: &Path, key: &Option<String>) -> Result<Self> {
        let conn = open_cipher_conn(path, key)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS compactblocks (
                height INTEGER PRIMARY KEY,
                data BLOB NOT NULL
            )"
        )?;
        Ok(Self { conn })
    }

    fn insert_blocks(&self, blocks: &[CompactBlock]) -> Result<(), rusqlite::Error> {
        let tx = self.conn.unchecked_transaction()?;
        {
            let mut stmt = self.conn.prepare_cached(
                "INSERT OR REPLACE INTO compactblocks (height, data) VALUES (?, ?)",
            )?;
            for block in blocks {
                let data = block.encode_to_vec();
                stmt.execute(rusqlite::params![block.height as u32, data])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    fn clear_range(&self, start: u32, end: u32) -> Result<(), rusqlite::Error> {
        self.conn.execute(
            "DELETE FROM compactblocks WHERE height >= ? AND height < ?",
            rusqlite::params![start, end],
        )?;
        Ok(())
    }
}

impl BlockSource for BlockCache {
    type Error = BlockCacheError;

    fn with_blocks<F, WalletErrT>(
        &self,
        from_height: Option<BlockHeight>,
        limit: Option<usize>,
        mut with_block: F,
    ) -> std::result::Result<
        (),
        zcash_client_backend::data_api::chain::error::Error<WalletErrT, Self::Error>,
    >
    where
        F: FnMut(
            CompactBlock,
        ) -> std::result::Result<
            (),
            zcash_client_backend::data_api::chain::error::Error<WalletErrT, Self::Error>,
        >,
    {
        use zcash_client_backend::data_api::chain::error::Error as ChainError;

        let from = from_height.map(u32::from).unwrap_or(0);
        let lim = limit.unwrap_or(u32::MAX as usize) as u32;

        let mut stmt = self
            .conn
            .prepare_cached(
                "SELECT height, data FROM compactblocks WHERE height >= ? ORDER BY height ASC LIMIT ?",
            )
            .map_err(|e| ChainError::BlockSource(BlockCacheError::from(e)))?;

        let rows = stmt
            .query_map(rusqlite::params![from, lim], |row| {
                let data: Vec<u8> = row.get(1)?;
                Ok(data)
            })
            .map_err(|e| ChainError::BlockSource(BlockCacheError::from(e)))?;

        for row in rows {
            let data =
                row.map_err(|e| ChainError::BlockSource(BlockCacheError::from(e)))?;
            let block = CompactBlock::decode(&data[..])
                .map_err(|e| ChainError::BlockSource(BlockCacheError(e.to_string())))?;
            with_block(block)?;
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Sync loop with exponential backoff retry
// ---------------------------------------------------------------------------

async fn sync_loop_with_retry(
    db_data_path: &Path,
    db_cache_path: &Path,
    params: Network,
    server_url: &str,
    db_cipher_key: &Option<String>,
) -> Result<()> {
    let mut backoff_ms: u64 = 5_000;
    const MAX_BACKOFF_MS: u64 = 60_000;
    let mut first_pass = true;

    loop {
        if SYNC_CANCEL.load(Ordering::SeqCst) {
            return Err(anyhow::anyhow!("Sync cancelled"));
        }

        match sync_loop(db_data_path, db_cache_path, params, server_url, db_cipher_key, first_pass).await {
            Ok(()) => {
                first_pass = false;
                {
                    let mut p = SYNC_PROGRESS.lock().await;
                    p.connection_error = None;
                }

                for _ in 0..30 {
                    if SYNC_CANCEL.load(Ordering::SeqCst) {
                        return Ok(());
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
                backoff_ms = 5_000;
            }
            Err(e) => {
                let msg = format!("{:?}", e);
                if msg.contains("Sync cancelled") {
                    return Err(e);
                }

                tracing::warn!("[engine sync] error, retrying in {}ms: {}", backoff_ms, msg);
                {
                    let mut p = SYNC_PROGRESS.lock().await;
                    p.connection_error = Some(msg);
                }

                let sleep_chunks = backoff_ms / 1000;
                for _ in 0..sleep_chunks {
                    if SYNC_CANCEL.load(Ordering::SeqCst) {
                        return Err(anyhow::anyhow!("Sync cancelled"));
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }

                backoff_ms = (backoff_ms * 2).min(MAX_BACKOFF_MS);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Core sync loop (single pass)
// ---------------------------------------------------------------------------

async fn sync_loop(
    db_data_path: &Path,
    db_cache_path: &Path,
    params: Network,
    server_url: &str,
    db_cipher_key: &Option<String>,
    update_roots: bool,
) -> Result<()> {
    tracing::info!("[engine sync] starting sync loop, server={}", server_url);

    let mut db_data = open_wallet_db(db_data_path, params, db_cipher_key)?;
    let db_cache = BlockCache::open(db_cache_path, db_cipher_key)?;
    tracing::info!("[engine sync] connecting to LWD...");
    let mut lwd = connect_lwd(server_url).await?;

    if update_roots {
        tracing::info!("[engine sync] connected, updating subtree roots...");
        update_subtree_roots(&mut lwd, &mut db_data, db_data_path, db_cipher_key).await?;
        tracing::info!("[engine sync] subtree roots done, entering scan loop");
    } else {
        tracing::info!("[engine sync] connected, skipping subtree roots (already done)");
    }

    let batch_size: u32 = 100;
    let mut consecutive_rewinds: u32 = 0;

    loop {
        if SYNC_CANCEL.load(Ordering::SeqCst) {
            return Err(anyhow::anyhow!("Sync cancelled"));
        }

        tracing::info!("[engine sync] fetching chain tip...");
        let tip = lwd
            .get_latest_block(ChainSpec::default())
            .await
            .map_err(|e| anyhow::anyhow!("get_latest_block: {:?}", e))?;
        let tip_height = BlockHeight::from_u32(tip.into_inner().height as u32);
        tracing::info!("[engine sync] chain tip = {}", u32::from(tip_height));

        db_data
            .update_chain_tip(tip_height)
            .map_err(|e| anyhow::anyhow!("update_chain_tip: {:?}", e))?;

        {
            let mut p = SYNC_PROGRESS.lock().await;
            p.latest_height = u32::from(tip_height);
            p.connection_error = None;
        }

        if let Err(e) = refresh_transparent_utxos(&mut lwd, &mut db_data, &params).await {
            tracing::warn!("[engine sync] transparent UTXO refresh warning: {:?}", e);
        }

        tracing::info!("[engine sync] querying scan ranges...");
        let scan_ranges = db_data
            .suggest_scan_ranges()
            .map_err(|e| anyhow::anyhow!("suggest_scan_ranges: {:?}", e))?;

        let has_work = scan_ranges
            .iter()
            .any(|range| range.priority() > ScanPriority::Scanned);
        if has_work {
            SYNC_CAUGHT_UP.store(false, Ordering::SeqCst);
        }

        if scan_ranges.is_empty() {
            tracing::info!("[engine sync] no more ranges to scan, done");
            let fsh = db_data
                .get_wallet_summary(ConfirmationsPolicy::default())
                .ok()
                .flatten()
                .map(|s| u32::from(s.fully_scanned_height()))
                .unwrap_or(0);
            if fsh > 0 {
                let mut p = SYNC_PROGRESS.lock().await;
                p.synced_height = fsh;
                p.latest_height = u32::from(tip_height);
                tracing::info!("[engine sync] set synced_height to fully_scanned_height={}", fsh);
            }
            if !has_work && fsh > 0 {
                SYNC_CAUGHT_UP.store(true, Ordering::SeqCst);
            }
            break;
        }

        for range in &scan_ranges {
            tracing::info!(
                "[engine sync] range {:?} priority={:?}",
                range.block_range(),
                range.priority()
            );
        }

        tracing::info!("[engine sync] {} scan ranges to process", scan_ranges.len());

        let mut any_scanned = false;
        // Set when a reorg rewind invalidated the scan ranges of this pass.
        let mut rewound = false;

        for range in &scan_ranges {
            if rewound {
                break;
            }
            if range.priority() <= ScanPriority::Scanned {
                continue;
            }

            if SYNC_CANCEL.load(Ordering::SeqCst) {
                return Err(anyhow::anyhow!("Sync cancelled"));
            }

            let range_start = range.block_range().start;
            let range_end = range.block_range().end;
            tracing::info!(
                "[engine sync] scanning range {:?} priority={:?}",
                range.block_range(),
                range.priority()
            );

            let mut current = range_start;
            while current < range_end {
                if SYNC_CANCEL.load(Ordering::SeqCst) {
                    return Err(anyhow::anyhow!("Sync cancelled"));
                }

                let batch_end = std::cmp::min(
                    current + batch_size,
                    range_end,
                );

                tracing::info!(
                    "[engine sync] downloading blocks {}..{}",
                    u32::from(current), u32::from(batch_end)
                );
                let blocks = download_blocks(&mut lwd, current, batch_end).await?;
                tracing::info!(
                    "[engine sync] downloaded {} blocks, scanning...",
                    blocks.len()
                );
                if blocks.is_empty() {
                    break;
                }
                // The chain state the batch is scanned from must describe the
                // block the batch actually builds on: pin it to the first
                // block's `prevHash` (see `download_chain_state`).
                let chain_state =
                    download_chain_state(&mut lwd, current, parent_hash_of_batch(&blocks, current))
                        .await?;

                db_cache
                    .insert_blocks(&blocks)
                    .map_err(|e| anyhow::anyhow!("insert_blocks: {:?}", e))?;

                {
                    let mut p = SYNC_PROGRESS.lock().await;
                    p.scanning_up_to = u32::from(batch_end);
                }

                let batch_len = u32::from(batch_end) - u32::from(current);
                let scan_result = tokio::task::block_in_place(|| {
                    scan_cached_blocks(
                        &params,
                        &db_cache,
                        &mut db_data,
                        current,
                        &chain_state,
                        batch_len as usize,
                    )
                });

                match scan_result {
                    Ok(summary) => {
                        consecutive_rewinds = 0;
                        let scanned_end = u32::from(summary.scanned_range().end);
                        let scanned = scanned_end
                            - u32::from(summary.scanned_range().start);
                        let notes = summary.received_sapling_note_count()
                            + summary.received_orchard_note_count();
                        tracing::info!(
                            "[engine sync] scanned {} blocks up to {}, {} notes found",
                            scanned, scanned_end, notes
                        );

                        {
                            let mut p = SYNC_PROGRESS.lock().await;
                            p.synced_height = scanned_end;
                        }
                    }
                    Err(ChainError::Scan(scan_err)) if scan_err.is_continuity_error() => {
                        // The blocks do not connect to what the wallet has
                        // already scanned: a chain reorganisation. The wallet
                        // DB's own record of the block below is stale, so
                        // rewinding to just below the failing block is not
                        // enough (if the wallet had scanned the replaced tip
                        // T, block T+1 fails and "T" is exactly what must
                        // go). Rewind well below it, as upstream does.
                        db_cache
                            .clear_range(u32::from(current), u32::from(batch_end))
                            .ok();
                        let at_height = scan_err.at_height();
                        let rewind_to = at_height.saturating_sub(REORG_REWIND_BLOCKS);
                        tracing::warn!(
                            "[engine sync] chain reorg detected at {} ({:?}); rewinding to {}",
                            u32::from(at_height),
                            scan_err,
                            u32::from(rewind_to)
                        );
                        let truncated_to = db_data
                            .truncate_to_height(rewind_to)
                            .map_err(|e| anyhow::anyhow!("truncate_to_height: {:?}", e))?;
                        tracing::info!(
                            "[engine sync] wallet rewound to {}",
                            u32::from(truncated_to)
                        );
                        {
                            let mut p = SYNC_PROGRESS.lock().await;
                            p.synced_height = u32::from(truncated_to);
                        }

                        // Back off before rescanning.
                        let pause = (REORG_BACKOFF_SECS << consecutive_rewinds.min(4))
                            .min(REORG_BACKOFF_MAX_SECS);
                        consecutive_rewinds = consecutive_rewinds.saturating_add(1);
                        for _ in 0..pause {
                            if SYNC_CANCEL.load(Ordering::SeqCst) {
                                return Err(anyhow::anyhow!("Sync cancelled"));
                            }
                            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                        }
                        // The scan ranges are stale now: ask the wallet again.
                        rewound = true;
                        break;
                    }
                    Err(e) => {
                        // Not a reorg (wallet / block-source error, or a scan
                        // error that is not about continuity): leave this
                        // range for the next pass.
                        tracing::warn!("[engine sync] scan error: {:?}", e);
                        db_cache
                            .clear_range(u32::from(current), u32::from(batch_end))
                            .ok();
                        break;
                    }
                }

                db_cache
                    .clear_range(u32::from(current), u32::from(batch_end))
                    .ok();

                {
                    let mut p = SYNC_PROGRESS.lock().await;
                    p.synced_height = u32::from(batch_end);
                    p.latest_height = u32::from(tip_height);
                    p.is_syncing = true;
                }

                current = batch_end;
                any_scanned = true;
            }
        }

        if rewound {
            continue;
        }

        if !any_scanned {
            tracing::info!("[engine sync] no actionable ranges, checking fully_scanned_height");
            let fsh = db_data
                .get_wallet_summary(ConfirmationsPolicy::default())
                .ok()
                .flatten()
                .map(|s| u32::from(s.fully_scanned_height()))
                .unwrap_or(0);
            if fsh > 0 {
                let mut p = SYNC_PROGRESS.lock().await;
                p.synced_height = fsh;
                p.latest_height = u32::from(tip_height);
                tracing::info!("[engine sync] set synced_height to fully_scanned_height={}", fsh);
            }
            if !has_work && fsh > 0 {
                SYNC_CAUGHT_UP.store(true, Ordering::SeqCst);
            }
            break;
        }
    }

    tracing::info!("[engine sync] sync loop finished");
    Ok(())
}

// ---------------------------------------------------------------------------
// Background sync for inactive wallets
// ---------------------------------------------------------------------------

#[allow(dead_code)]
async fn sync_inactive_wallets(
    params: Network,
    server_url: &str,
    db_cipher_key: &Option<String>,
) {
    let wallets = INACTIVE_WALLETS.lock().await.clone();
    if wallets.is_empty() {
        return;
    }

    tracing::info!("[engine sync] syncing {} inactive wallet(s)", wallets.len());

    for wallet in &wallets {
        if SYNC_CANCEL.load(Ordering::SeqCst) {
            return;
        }

        if !wallet.db_data_path.exists() {
            continue;
        }

        if let Err(e) = sync_inactive_wallet_batch(
            &wallet.db_data_path,
            &wallet.db_cache_path,
            params,
            server_url,
            db_cipher_key,
        )
        .await
        {
            tracing::info!(
                "[engine sync] inactive wallet {:?} error: {:?}",
                wallet.db_data_path, e
            );
        }
    }
}

#[allow(dead_code)]
async fn sync_inactive_wallet_batch(
    db_data_path: &Path,
    db_cache_path: &Path,
    params: Network,
    server_url: &str,
    db_cipher_key: &Option<String>,
) -> Result<()> {
    let mut db_data = open_wallet_db(db_data_path, params, db_cipher_key)?;
    let db_cache = BlockCache::open(db_cache_path, db_cipher_key)?;
    let mut lwd = connect_lwd(server_url).await?;

    let tip = lwd
        .get_latest_block(ChainSpec::default())
        .await
        .map_err(|e| anyhow::anyhow!("get_latest_block: {:?}", e))?;
    let tip_height = BlockHeight::from_u32(tip.into_inner().height as u32);

    db_data
        .update_chain_tip(tip_height)
        .map_err(|e| anyhow::anyhow!("update_chain_tip: {:?}", e))?;

    let scan_ranges = db_data
        .suggest_scan_ranges()
        .map_err(|e| anyhow::anyhow!("suggest_scan_ranges: {:?}", e))?;

    let batch_size: u32 = 500;

    for range in &scan_ranges {
        if range.priority() <= ScanPriority::Scanned {
            continue;
        }

        if SYNC_CANCEL.load(Ordering::SeqCst) {
            return Ok(());
        }

        let range_start = range.block_range().start;
        let batch_end = std::cmp::min(range_start + batch_size, range.block_range().end);

        let blocks = download_blocks(&mut lwd, range_start, batch_end).await?;
        if blocks.is_empty() {
            break;
        }
        let chain_state =
            download_chain_state(&mut lwd, range_start, parent_hash_of_batch(&blocks, range_start))
                .await?;

        db_cache
            .insert_blocks(&blocks)
            .map_err(|e| anyhow::anyhow!("insert_blocks: {:?}", e))?;

        let batch_len = u32::from(batch_end) - u32::from(range_start);
        let _ = scan_cached_blocks(
            &params,
            &db_cache,
            &mut db_data,
            range_start,
            &chain_state,
            batch_len as usize,
        );

        db_cache
            .clear_range(u32::from(range_start), u32::from(batch_end))
            .ok();

        break;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Query the next free shard index for a given tree table.
/// Returns 0 if no shards exist yet, otherwise MAX(shard_index) + 1.
fn next_shard_index(
    db_data_path: &Path,
    cipher_key: &Option<String>,
    table_prefix: &str,
) -> u64 {
    let conn = match super::open_cipher_conn(db_data_path, cipher_key) {
        Ok(c) => c,
        Err(_) => return 0,
    };
    let sql = format!(
        "SELECT MAX(shard_index) FROM {}_tree_shards",
        table_prefix
    );
    conn.query_row(&sql, [], |row| row.get::<_, Option<u64>>(0))
        .unwrap_or(None)
        .map(|max| max + 1)
        .unwrap_or(0)
}

async fn update_subtree_roots(
    lwd: &mut CompactTxStreamerClient<tonic::transport::Channel>,
    db_data: &mut WalletDb<rusqlite::Connection, Network, zcash_client_sqlite::util::SystemClock, super::WalletRng>,
    db_data_path: &Path,
    db_cipher_key: &Option<String>,
) -> Result<()> {
    use futures_util::TryStreamExt;

    // --- Sapling ---
    let sapling_start = next_shard_index(db_data_path, db_cipher_key, "sapling");

    let mut sapling_request = GetSubtreeRootsArg::default();
    sapling_request.set_shielded_protocol(ShieldedProtocol::Sapling);
    sapling_request.start_index = sapling_start as u32;

    let sapling_stream = lwd
        .get_subtree_roots(sapling_request)
        .await
        .map_err(|e| anyhow::anyhow!("get_subtree_roots(sapling): {:?}", e))?
        .into_inner();

    let sapling_roots: Vec<CommitmentTreeRoot<sapling_crypto::Node>> = sapling_stream
        .and_then(|root| async move {
            let root_hash = sapling_crypto::Node::read(&root.root_hash[..])
                .map_err(|e| tonic::Status::internal(format!("{:?}", e)))?;
            Ok(CommitmentTreeRoot::from_parts(
                BlockHeight::from_u32(root.completing_block_height as u32),
                root_hash,
            ))
        })
        .try_collect()
        .await
        .map_err(|e| anyhow::anyhow!("sapling subtree roots: {:?}", e))?;

    tracing::info!(
        "[engine sync] {} new sapling subtree roots (start_index={})",
        sapling_roots.len(),
        sapling_start,
    );
    if !sapling_roots.is_empty() {
        db_data
            .put_sapling_subtree_roots(sapling_start, &sapling_roots)
            .map_err(|e| anyhow::anyhow!("put_sapling_subtree_roots: {:?}", e))?;
    }

    // --- Orchard ---
    let orchard_start = next_shard_index(db_data_path, db_cipher_key, "orchard");

    let mut orchard_request = GetSubtreeRootsArg::default();
    orchard_request.set_shielded_protocol(ShieldedProtocol::Orchard);
    orchard_request.start_index = orchard_start as u32;

    let orchard_stream = lwd
        .get_subtree_roots(orchard_request)
        .await
        .map_err(|e| anyhow::anyhow!("get_subtree_roots(orchard): {:?}", e))?
        .into_inner();

    let orchard_roots: Vec<CommitmentTreeRoot<orchard::tree::MerkleHashOrchard>> = orchard_stream
        .and_then(|root| async move {
            let root_hash = orchard::tree::MerkleHashOrchard::read(&root.root_hash[..])
                .map_err(|e| tonic::Status::internal(format!("{:?}", e)))?;
            Ok(CommitmentTreeRoot::from_parts(
                BlockHeight::from_u32(root.completing_block_height as u32),
                root_hash,
            ))
        })
        .try_collect()
        .await
        .map_err(|e| anyhow::anyhow!("orchard subtree roots: {:?}", e))?;

    tracing::info!(
        "[engine sync] {} new orchard subtree roots (start_index={})",
        orchard_roots.len(),
        orchard_start,
    );
    if !orchard_roots.is_empty() {
        db_data
            .put_orchard_subtree_roots(orchard_start, &orchard_roots)
            .map_err(|e| anyhow::anyhow!("put_orchard_subtree_roots: {:?}", e))?;
    }

    Ok(())
}

/// The hash of the block a downloaded batch builds on: the `prevHash` of its
/// first block, provided that block is the one at `batch_start` and the
/// server populated the field. `None` means "cannot validate" (e.g. a server
/// that omits `prevHash`), in which case the tree state is taken on trust as
/// before.
fn parent_hash_of_batch(blocks: &[CompactBlock], batch_start: BlockHeight) -> Option<BlockHash> {
    let first = blocks.first()?;
    if first.height != u64::from(u32::from(batch_start)) {
        return None;
    }
    let parent = BlockHash::try_from_slice(&first.prev_hash)?;
    // An all-zero prevHash is what a server that does not fill the field
    // (or the genesis block) looks like; it is not a usable expectation.
    (parent.0 != [0u8; 32]).then_some(parent)
}

/// The block hash a lightwalletd `TreeState` claims to describe. The proto
/// carries it as a hex string in display (big-endian) order.
fn tree_state_block_hash(tree_state: &TreeState) -> Option<BlockHash> {
    let mut bytes = hex::decode(&tree_state.hash).ok()?;
    bytes.reverse();
    BlockHash::try_from_slice(&bytes)
}

fn tree_state_is_for(tree_state: &TreeState, height: BlockHeight, hash: Option<BlockHash>) -> bool {
    tree_state.height == u64::from(u32::from(height))
        && match hash {
            Some(expected) => tree_state_block_hash(tree_state) == Some(expected),
            None => true,
        }
}

async fn get_tree_state(
    lwd: &mut CompactTxStreamerClient<tonic::transport::Channel>,
    block_id: BlockId,
) -> Result<TreeState> {
    Ok(lwd
        .get_tree_state(block_id)
        .await
        .map_err(|e| anyhow::anyhow!("get_tree_state: {:?}", e))?
        .into_inner())
}

/// The hash of the block lightwalletd serves at `height` (`GetBlock`), i.e.
/// the block on the chain that `GetBlockRange` scanning will follow.
pub(crate) async fn fetch_block_hash(
    lwd: &mut CompactTxStreamerClient<tonic::transport::Channel>,
    height: BlockHeight,
) -> Result<BlockHash> {
    let block = lwd
        .get_block(BlockId {
            height: u64::from(u32::from(height)),
            hash: vec![],
        })
        .await
        .map_err(|e| anyhow::anyhow!("get_block({}): {:?}", u32::from(height), e))?
        .into_inner();
    if block.height != u64::from(u32::from(height)) {
        return Err(anyhow::anyhow!(
            "get_block({}) returned block {}",
            u32::from(height),
            block.height
        ));
    }
    BlockHash::try_from_slice(&block.hash)
        .filter(|h| h.0 != [0u8; 32])
        .ok_or_else(|| anyhow::anyhow!("get_block({}) returned no block hash", u32::from(height)))
}

/// Fetch the tree state (note commitment tree frontiers) as of the end of
/// block `height`, and make sure it really is the state of the block the
/// caller means.
///
/// `expected_hash` is the hash that block must have (for a scan batch: the
/// `prevHash` of the batch's first block; for a wallet birthday: the hash
/// `GetBlock` serves at that height). A lightwalletd `GetTreeState` *by
/// height* is answered by the backing node's `z_gettreestate <height>`, and a
/// node can resolve a height to a block that is not on the chain its
/// `GetBlock` / `GetBlockRange` serve. Observed on `testnet.zec.rocks`
/// (Zakura 1.7.0 behind lightwalletd v0.6.1): scattered heights — about a
/// hundred in 4349563..4349850, and others later, e.g. 4566443, after NU7
/// activation, so this is not a one-off historical patch — return the tree
/// state of a stale side-chain block with a different hash, timestamp and
/// tree sizes. Scanning from such a state fails every time with
/// `NonSequentialBlocks` (the frontier sizes do not line up with the first
/// block's), and a wallet whose *birthday* frontier came from one could
/// never build a valid witness.
///
/// So the by-height answer is only accepted if its height is the one asked
/// for and its block hash is the expected one. Otherwise the tree state is
/// requested *by hash*, which names the exact block, and the answer is
/// checked again. If no consistent state can be obtained an error is
/// returned rather than handing the wallet frontiers from another chain.
///
/// With `expected_hash == None` (a server that omits `prevHash`) only the
/// height can be checked.
pub(crate) async fn fetch_validated_tree_state(
    lwd: &mut CompactTxStreamerClient<tonic::transport::Channel>,
    height: BlockHeight,
    expected_hash: Option<BlockHash>,
) -> Result<TreeState> {
    let by_height = get_tree_state(
        lwd,
        BlockId {
            height: u64::from(u32::from(height)),
            hash: vec![],
        },
    )
    .await?;
    if tree_state_is_for(&by_height, height, expected_hash) {
        return Ok(by_height);
    }
    let Some(expected) = expected_hash else {
        return Err(anyhow::anyhow!(
            "lightwalletd returned the tree state of height {} when asked for height {}",
            by_height.height,
            u32::from(height),
        ));
    };

    tracing::warn!(
        "[engine sync] tree state by height {} is for block {} (height {}) but the chain being \
         followed has {} there; re-requesting the tree state by block hash",
        u32::from(height),
        by_height.hash,
        by_height.height,
        expected,
    );

    // lightwalletd only looks at `BlockID.hash` when `BlockID.height` is 0
    // (a non-zero height wins and reproduces the by-height answer), so the
    // by-hash request must leave the height unset. It hex-encodes the hash
    // as-is into `z_gettreestate`, so it wants the display (big-endian, RPC)
    // byte order; `BlockHash` holds the internal little-endian order used in
    // compact blocks. Try the display order first and the internal order
    // second (for a server that reverses it itself). Either answer is checked
    // for both hash and height, so neither the order nor a server that
    // ignores the hash can select a wrong block.
    let mut display_order = expected.0;
    display_order.reverse();
    let mut last_err = None;
    for hash in [display_order.to_vec(), expected.0.to_vec()] {
        match get_tree_state(lwd, BlockId { height: 0, hash }).await {
            Ok(state) if tree_state_is_for(&state, height, Some(expected)) => return Ok(state),
            Ok(state) => {
                last_err = Some(format!(
                    "by-hash tree state is for block {} at height {}",
                    state.hash, state.height,
                ));
            }
            Err(e) => last_err = Some(format!("{:?}", e)),
        }
    }

    Err(anyhow::anyhow!(
        "inconsistent lightwalletd tree state at height {}: expected block {}, got {} by height, \
         and by hash: {}",
        u32::from(height),
        expected,
        by_height.hash,
        last_err.unwrap_or_default(),
    ))
}

/// The chain state a batch starting at `block_height` is scanned from: the
/// validated tree state of the block before it (see
/// [`fetch_validated_tree_state`]). The returned state is always for height
/// `block_height - 1`, which `scan_cached_blocks` asserts.
async fn download_chain_state(
    lwd: &mut CompactTxStreamerClient<tonic::transport::Channel>,
    block_height: BlockHeight,
    expected_parent: Option<BlockHash>,
) -> Result<zcash_client_backend::data_api::chain::ChainState> {
    let prior_height = block_height - 1;
    let state = fetch_validated_tree_state(lwd, prior_height, expected_parent)
        .await?
        .to_chain_state()
        .map_err(|e| anyhow::anyhow!("to_chain_state: {:?}", e))?;
    if state.block_height() != prior_height {
        return Err(anyhow::anyhow!(
            "tree state height {} != {}",
            u32::from(state.block_height()),
            u32::from(prior_height)
        ));
    }
    Ok(state)
}

async fn download_blocks(
    lwd: &mut CompactTxStreamerClient<tonic::transport::Channel>,
    from: BlockHeight,
    to: BlockHeight,
) -> Result<Vec<CompactBlock>> {
    let range = BlockRange {
        start: Some(BlockId {
            height: u64::from(u32::from(from)),
            hash: vec![],
        }),
        end: Some(BlockId {
            height: u64::from(u32::from(to) - 1),
            hash: vec![],
        }),
        pool_types: vec![],
    };

    let mut stream = lwd
        .get_block_range(range)
        .await
        .map_err(|e| anyhow::anyhow!("get_block_range: {:?}", e))?
        .into_inner();

    let mut blocks = Vec::new();
    while let Some(block) = stream
        .message()
        .await
        .map_err(|e| anyhow::anyhow!("stream block: {:?}", e))?
    {
        blocks.push(block);
    }

    Ok(blocks)
}

// ---------------------------------------------------------------------------
// Transparent UTXO refresh
// ---------------------------------------------------------------------------

type DbType = WalletDb<rusqlite::Connection, Network, zcash_client_sqlite::util::SystemClock, super::WalletRng>;

async fn refresh_transparent_utxos(
    lwd: &mut CompactTxStreamerClient<tonic::transport::Channel>,
    db_data: &mut DbType,
    params: &Network,
) -> Result<()> {
    let account_ids = db_data
        .get_account_ids()
        .map_err(|e| anyhow::anyhow!("get_account_ids: {:?}", e))?;

    for account_id in account_ids {
        let start_height = db_data
            .utxo_query_height(account_id)
            .map_err(|e| anyhow::anyhow!("utxo_query_height: {:?}", e))?;

        let receivers = db_data
            .get_transparent_receivers(account_id, true, true)
            .map_err(|e| anyhow::anyhow!("get_transparent_receivers: {:?}", e))?;

        let addresses: Vec<String> = receivers
            .into_keys()
            .map(|addr| addr.encode(params))
            .collect();

        if addresses.is_empty() {
            continue;
        }

        tracing::info!(
            "[engine sync] refreshing transparent UTXOs for {:?} from height {} ({} addresses)",
            account_id, start_height, addresses.len()
        );

        let request = GetAddressUtxosArg {
            addresses,
            start_height: u64::from(u32::from(start_height)),
            max_entries: 0,
        };

        let reply_list = lwd
            .get_address_utxos(request)
            .await
            .map_err(|e| anyhow::anyhow!("get_address_utxos: {:?}", e))?;

        let utxos = reply_list.into_inner().address_utxos;
        let mut count = 0u32;

        for reply in utxos {
            let Ok(txid_arr) = reply.txid[..].try_into() else { continue };
            let Ok(index) = reply.index.try_into() else { continue };
            let Ok(value) = Zatoshis::from_nonnegative_i64(reply.value_zat) else { continue };
            let Ok(height) = BlockHeight::try_from(reply.height) else { continue };

            let outpoint = OutPoint::new(txid_arr, index);
            let txout = TxOut::new(value, Script(zcash_script::script::Code(reply.script)));

            // 292e7584: from_parts gained recipient_account / recipient_key_scope
            // / funding_account (all Option). We don't have them from a bare
            // UTXO reply, so pass None — the wallet backfills ownership on scan.
            if let Some(output) =
                WalletTransparentOutput::from_parts(outpoint, txout, Some(height), None, None, None)
            {
                db_data
                    .put_received_transparent_utxo(&output)
                    .map_err(|e| anyhow::anyhow!("put_received_transparent_utxo: {:?}", e))?;
                count += 1;
            }
        }

        if count > 0 {
            tracing::info!("[engine sync] stored {} transparent UTXOs for {:?}", count, account_id);
        }
    }

    Ok(())
}
