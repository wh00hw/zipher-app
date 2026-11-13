//! Hardware wallet signing via zcash-hw-signer-sdk.
//!
//! Provides PCZT-based transaction signing using external hardware devices.
//! The spending key never leaves the device — only the full viewing key (FVK)
//! is exported for address derivation and blockchain scanning.

use anyhow::Result;
use tracing::{info, error};

use zcash_client_backend::data_api::wallet::{
    create_pczt_from_proposal, extract_and_store_transaction_from_pczt,
};
use zcash_client_backend::data_api::WalletRead;
use zcash_client_backend::util::SystemClock;
use zcash_client_backend::wallet::OvkPolicy;
use zcash_client_backend::proto::service::RawTransaction;
use zcash_primitives::transaction::builder::BundlePadding;
use zcash_hw_wallet_sdk::{
    HardwareSigner, PcztHardwareSigning, TxDetails,
};

use super::wallet::connect_lwd;
use super::{open_wallet_db, ENGINE};

/// Sign and broadcast a pending proposal using a hardware wallet.
///
/// This is the hardware-wallet equivalent of `confirm_send()`. Instead of
/// deriving keys from a seed phrase, it:
/// 1. Creates a PCZT from the pending proposal (FVK-only, no spending key)
/// 2. Sends the PCZT to the hardware signer SDK for Orchard signing
/// 3. Extracts the signed transaction and stores it in the wallet DB
/// 4. Broadcasts to lightwalletd
pub async fn confirm_send_hw<S: HardwareSigner>(
    signer: S,
    address: &str,
    send_amount: u64,
    fee: u64,
    memo: Option<String>,
) -> Result<String> {
    info!("[HW-CONFIRM] ====== confirm_send_hw START ======");

    let proposal = {
        let mut lock = super::send::take_pending_proposal();
        lock.take()
            .ok_or_else(|| anyhow::anyhow!("No pending proposal — call propose_send first"))?
    };

    let engine_guard = ENGINE.lock().await;
    let engine = engine_guard
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Engine not initialized"))?;

    let db_data_path = engine.db_data_path.clone();
    let params = engine.params;
    let server_url = engine.server_url.clone();
    let db_cipher_key = engine.db_cipher_key.clone();
    drop(engine_guard);

    let mut db_data = open_wallet_db(&db_data_path, params, &db_cipher_key)?;

    let account_id = db_data
        .get_account_ids()
        .map_err(|e| anyhow::anyhow!("{:?}", e))?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("No accounts"))?;

    // Outgoing viewing keys for the outputs. `OvkPolicy::Sender` encrypts
    // payments under the external OVK but builds wallet-internal outputs
    // (change) with NO outgoing viewing key, which makes them impossible for
    // anyone but the incoming-viewing-key holder to open — including the
    // signing workflow, which must hand the device the full plaintext of
    // every value-carrying output and refuses the transaction otherwise.
    // So change is encrypted under the account's internal-scope OVK (the
    // ZIP 32 key meant for exactly this), and payments under the external
    // one as before. Both belong to the device's own account.
    let ovk_policy = {
        use zcash_client_backend::data_api::Account as _;
        let account = db_data
            .get_account(account_id)
            .map_err(|e| anyhow::anyhow!("{:?}", e))?
            .ok_or_else(|| anyhow::anyhow!("Account not found"))?;
        let ufvk = account
            .ufvk()
            .ok_or_else(|| anyhow::anyhow!("Account has no full viewing key"))?;
        let fvk = ufvk.orchard().ok_or_else(|| {
            anyhow::anyhow!("Account has no Orchard full viewing key (hardware accounts are Orchard-protocol only)")
        })?;
        OvkPolicy::Custom {
            external_ovk: zcash_keys::keys::OutgoingViewingKey::from(
                fvk.to_ovk(orchard::keys::Scope::External),
            ),
            internal_ovk: Some(zcash_keys::keys::OutgoingViewingKey::from(
                fvk.to_ovk(orchard::keys::Scope::Internal),
            )),
        }
    };

    // Step 1: Create PCZT from proposal (no spending key needed)
    info!("[HW-CONFIRM] Creating PCZT from proposal...");
    // zcash_client_backend 0.24: create_pczt_from_proposal takes
    // `expiry_height: Option<BlockHeight>` (None = default expiry) and
    // `orchard_pool_padding: BundlePadding` (DEFAULT = the previous padded
    // behaviour). The Ironwood bundle's padding is not caller-chosen: it is
    // derived from the proposal by `Step::ironwood_bundle_padding`.
    // zcash_client_backend 0.25: explicit clock + RNG arguments. With
    // `expiry_height = None` the default expiry is target height + 120
    // blocks once NU7 is active at the target height (25 s blocks; it was
    // + 40 under NU6.3), or the ZIP 318 canonical expiry for a pool-migration
    // crossing.
    let pczt = create_pczt_from_proposal::<_, _, std::convert::Infallible, _, std::convert::Infallible, _>(
        &mut db_data,
        &params,
        &SystemClock,
        &mut super::wallet_rng(),
        account_id,
        ovk_policy,
        &proposal,
        None,
        BundlePadding::DEFAULT,
    )
    .map_err(|e| {
        error!("[HW-CONFIRM] create_pczt_from_proposal FAILED: {:?}", e);
        anyhow::anyhow!("Create PCZT failed: {:?}", e)
    })?;

    // 292e7584: Pczt::serialize() is now fallible (deferred-anchor encoding).
    let pczt_bytes = pczt
        .serialize()
        .map_err(|e| anyhow::anyhow!("PCZT serialization failed: {:?}", e))?;
    info!("[HW-CONFIRM] PCZT created: {} bytes", pczt_bytes.len());

    // Step 2: Sign via hardware wallet
    let tx_details = TxDetails {
        send_amount,
        fee,
        recipient: address.to_string(),
        num_actions: 0, // filled by workflow
        memo,
    };

    info!("[HW-CONFIRM] Sending PCZT to hardware signer...");
    let mut workflow = PcztHardwareSigning::new(signer);
    let result = workflow.sign_with_details(pczt_bytes, Some(tx_details))
        .map_err(|e| {
            error!("[HW-CONFIRM] Hardware signing FAILED: {:?}", e);
            anyhow::anyhow!("Hardware signing failed: {:?}", e)
        })?;

    info!(
        "[HW-CONFIRM] Hardware signed OK: {} orchard action(s), {} transparent input(s)",
        result.actions_signed, result.transparent_inputs_signed,
    );

    // Step 3: Parse signed PCZT and extract transaction
    let signed_pczt = pczt::Pczt::parse(&result.signed_pczt)
        .map_err(|e| anyhow::anyhow!("Parse signed PCZT failed: {:?}", e))?;

    // orchard 0.15+: VerifyingKey::build takes the circuit version. The signed
    // tx is a v6 transaction under NU6.3 or NU7 — both select Orchard
    // protocol revision V3, so Ironwood / sealed-Orchard both use the
    // PostNu6_3 circuit, and this VK verifies both bundles' proofs.
    let orchard_vk =
        orchard::circuit::VerifyingKey::build(orchard::circuit::OrchardCircuitVersion::PostNu6_3);
    let txid = extract_and_store_transaction_from_pczt::<_, zcash_client_sqlite::ReceivedNoteId>(
        &mut db_data,
        &SystemClock,
        &mut super::wallet_rng(),
        signed_pczt,
        None, // no sapling VK needed for Orchard-only
        Some(&orchard_vk),
    )
    .map_err(|e| {
        error!("[HW-CONFIRM] extract_and_store FAILED: {:?}", e);
        anyhow::anyhow!("Extract transaction failed: {:?}", e)
    })?;

    info!("[HW-CONFIRM] Transaction extracted. txid={}", txid);

    // Step 4: Fetch and broadcast. From here on the signed transaction is
    // stored in the wallet DB and its inputs are reserved until it is mined
    // or expires, so every failure is reported as `BroadcastFailed` carrying
    // the txid: the caller can retry with `rebroadcast` (the signed bytes are
    // in the DB; the device is not needed again).
    let tx = db_data
        .get_transaction(txid)
        .map_err(|e| anyhow::anyhow!("{:?}", e))?
        .ok_or_else(|| anyhow::anyhow!("Transaction {} not found after extraction", txid))?;
    let expiry_height = u32::from(tx.expiry_height());
    let mut tx_bytes = Vec::new();
    tx.write(&mut tx_bytes)
        .map_err(|e| anyhow::anyhow!("Serialize tx {}: {:?}", txid, e))?;
    info!("[HW-CONFIRM] Serialized tx: {} bytes", tx_bytes.len());

    info!("[HW-CONFIRM] Broadcasting to {}...", server_url);
    if let Err(failure) = broadcast_raw(&server_url, tx_bytes).await {
        error!("[HW-CONFIRM] Broadcast of {} FAILED: {:?}", txid, failure);
        return Err(BroadcastFailed {
            txid: txid.to_string(),
            expiry_height,
            rejected_by_node: failure.rejected_by_node,
            reason: failure.reason,
        }
        .into());
    }

    info!("[HW-CONFIRM] ====== confirm_send_hw SUCCESS txid={} ======", txid);
    Ok(txid.to_string())
}

/// A transaction that was signed and stored in the wallet, but whose
/// broadcast did not succeed.
#[derive(Debug, Clone)]
pub struct BroadcastFailed {
    pub txid: String,
    /// The transaction's expiry height (0 = no expiry). Its inputs are
    /// reserved by the wallet until it is mined or this height passes.
    pub expiry_height: u32,
    /// `true` if the node answered and refused the transaction; `false` if
    /// the request itself failed (network / server error), in which case the
    /// node may or may not have received it.
    pub rejected_by_node: bool,
    pub reason: String,
}

impl std::fmt::Display for BroadcastFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "transaction {} was signed and stored but not broadcast ({}: {}). Its inputs stay \
             reserved until it is mined or expires at height {}. Retry with `send rebroadcast \
             --txid {}` (no device needed).",
            self.txid,
            if self.rejected_by_node { "rejected by the node" } else { "send failed" },
            self.reason,
            self.expiry_height,
            self.txid,
        )
    }
}

impl std::error::Error for BroadcastFailed {}

struct RawBroadcastError {
    rejected_by_node: bool,
    reason: String,
}

impl std::fmt::Debug for RawBroadcastError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "rejected_by_node={} {}", self.rejected_by_node, self.reason)
    }
}

async fn broadcast_raw(server_url: &str, tx_bytes: Vec<u8>) -> std::result::Result<(), RawBroadcastError> {
    let transport_err = |reason: String| RawBroadcastError { rejected_by_node: false, reason };
    let mut lwd = connect_lwd(server_url)
        .await
        .map_err(|e| transport_err(format!("connect: {:#}", e)))?;
    let resp = lwd
        .send_transaction(RawTransaction { data: tx_bytes, height: 0 })
        .await
        .map_err(|e| transport_err(format!("{:?}", e)))?
        .into_inner();
    if resp.error_code != 0 {
        return Err(RawBroadcastError {
            rejected_by_node: true,
            reason: format!("{} (code {})", resp.error_message, resp.error_code),
        });
    }
    Ok(())
}

/// What `rebroadcast` did.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RebroadcastOutcome {
    pub txid: String,
    pub expiry_height: u32,
    pub chain_tip: u32,
}

/// Send again a transaction the wallet already holds in signed form (e.g.
/// one whose first broadcast failed). Nothing is re-signed.
///
/// Refuses a transaction that is already mined, and one that has expired:
/// a transaction with expiry height `E` can only be mined in a block of
/// height <= `E`, so it is dead once the chain tip has reached `E`.
pub async fn rebroadcast(txid_hex: &str) -> Result<RebroadcastOutcome> {
    let mut txid_bytes: [u8; 32] = hex::decode(txid_hex.trim())
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| anyhow::anyhow!("txid must be 64 hex characters"))?;
    txid_bytes.reverse(); // display order -> internal order
    let txid = zcash_primitives::transaction::TxId::from_bytes(txid_bytes);

    let engine_guard = ENGINE.lock().await;
    let engine = engine_guard
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Engine not initialized"))?;
    let db_data_path = engine.db_data_path.clone();
    let params = engine.params;
    let server_url = engine.server_url.clone();
    let db_cipher_key = engine.db_cipher_key.clone();
    drop(engine_guard);

    let db_data = open_wallet_db(&db_data_path, params, &db_cipher_key)?;
    if let Some(height) = db_data
        .get_tx_height(txid)
        .map_err(|e| anyhow::anyhow!("{:?}", e))?
    {
        return Err(anyhow::anyhow!(
            "transaction {} is already mined (height {})",
            txid,
            u32::from(height)
        ));
    }
    let tx = db_data
        .get_transaction(txid)
        .map_err(|e| anyhow::anyhow!("{:?}", e))?
        .ok_or_else(|| anyhow::anyhow!("transaction {} is not in this wallet", txid))?;
    let expiry_height = u32::from(tx.expiry_height());

    let chain_tip = u32::try_from(super::wallet::fetch_latest_height(&server_url).await?)
        .map_err(|_| anyhow::anyhow!("chain tip out of range"))?;
    if expiry_height != 0 && chain_tip >= expiry_height {
        return Err(anyhow::anyhow!(
            "transaction {} expired at height {} (chain tip is {}): it can no longer be mined. \
             Its inputs are spendable again once the wallet has synced past that height; create \
             a new proposal.",
            txid,
            expiry_height,
            chain_tip
        ));
    }

    let mut tx_bytes = Vec::new();
    tx.write(&mut tx_bytes)
        .map_err(|e| anyhow::anyhow!("Serialize tx {}: {:?}", txid, e))?;
    broadcast_raw(&server_url, tx_bytes).await.map_err(|f| {
        anyhow::Error::new(BroadcastFailed {
            txid: txid.to_string(),
            expiry_height,
            rejected_by_node: f.rejected_by_node,
            reason: f.reason,
        })
    })?;
    info!("[REBROADCAST] {} accepted (expiry {}, tip {})", txid, expiry_height, chain_tip);
    Ok(RebroadcastOutcome { txid: txid.to_string(), expiry_height, chain_tip })
}

/// Pair a hardware device: export FVK and create a watch-only wallet.
///
/// 1. Exports the Orchard FVK from the device via the SDK
/// 2. Encodes it as a UFVK using `ExportedFvk::to_ufvk_string`
/// 3. Creates a watch-only wallet via `restore_from_ufvk`
pub async fn pair_device<S: HardwareSigner>(
    mut signer: S,
    data_dir: &str,
    server_url: &str,
    params: zcash_protocol::consensus::Network,
    birthday_height: u32,
    db_cipher_key: Option<String>,
) -> Result<(zcash_hw_wallet_sdk::ExportedFvk, String)> {
    info!("[HW-PAIR] Requesting FVK export from hardware device...");
    let fvk = signer.export_fvk().map_err(|e| {
        error!("[HW-PAIR] FVK export failed: {:?}", e);
        anyhow::anyhow!("FVK export failed: {:?}", e)
    })?;
    // The FVK components are viewing-key material: never logged.
    info!("[HW-PAIR] FVK exported.");

    let ufvk_str = fvk.to_ufvk_string(&params)
        .map_err(|e| anyhow::anyhow!("UFVK encoding failed: {:?}", e))?;
    info!("[HW-PAIR] UFVK encoded. Creating watch-only wallet...");

    super::wallet::restore_from_ufvk(
        data_dir,
        server_url,
        params,
        &ufvk_str,
        birthday_height,
        db_cipher_key,
    )
    .await?;

    info!("[HW-PAIR] Watch-only wallet created. Ready to sync.");
    Ok((fvk, ufvk_str))
}
