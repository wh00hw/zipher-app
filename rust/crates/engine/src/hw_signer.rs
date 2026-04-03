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
use zcash_client_backend::wallet::OvkPolicy;
use zcash_client_backend::proto::service::RawTransaction;
use zcash_hw_signer_sdk::{
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

    // Step 1: Create PCZT from proposal (no spending key needed)
    info!("[HW-CONFIRM] Creating PCZT from proposal...");
    let pczt = create_pczt_from_proposal::<_, _, std::convert::Infallible, _, std::convert::Infallible, _>(
        &mut db_data,
        &params,
        account_id,
        OvkPolicy::Sender,
        &proposal,
    )
    .map_err(|e| {
        error!("[HW-CONFIRM] create_pczt_from_proposal FAILED: {:?}", e);
        anyhow::anyhow!("Create PCZT failed: {:?}", e)
    })?;

    let pczt_bytes = pczt.serialize();
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
        "[HW-CONFIRM] Hardware signed OK: {} action(s)",
        result.actions_signed
    );

    // Step 3: Parse signed PCZT and extract transaction
    let signed_pczt = pczt::Pczt::parse(&result.signed_pczt)
        .map_err(|e| anyhow::anyhow!("Parse signed PCZT failed: {:?}", e))?;

    let orchard_vk = orchard::circuit::VerifyingKey::build();
    let txid = extract_and_store_transaction_from_pczt::<_, zcash_client_sqlite::ReceivedNoteId>(
        &mut db_data,
        signed_pczt,
        None, // no sapling VK needed for Orchard-only
        Some(&orchard_vk),
    )
    .map_err(|e| {
        error!("[HW-CONFIRM] extract_and_store FAILED: {:?}", e);
        anyhow::anyhow!("Extract transaction failed: {:?}", e)
    })?;

    info!("[HW-CONFIRM] Transaction extracted. txid={}", txid);

    // Step 4: Fetch and broadcast
    let tx = db_data
        .get_transaction(txid)
        .map_err(|e| anyhow::anyhow!("{:?}", e))?
        .ok_or_else(|| anyhow::anyhow!("Transaction not found after extraction"))?;
    let mut tx_bytes = Vec::new();
    tx.write(&mut tx_bytes)
        .map_err(|e| anyhow::anyhow!("Serialize tx: {:?}", e))?;
    info!("[HW-CONFIRM] Serialized tx: {} bytes", tx_bytes.len());

    info!("[HW-CONFIRM] Broadcasting to {}...", server_url);
    let mut lwd = connect_lwd(&server_url).await?;
    let resp = lwd
        .send_transaction(RawTransaction {
            data: tx_bytes,
            height: 0,
        })
        .await
        .map_err(|e| {
            error!("[HW-CONFIRM] Broadcast FAILED: {:?}", e);
            anyhow::anyhow!("Broadcast failed: {:?}", e)
        })?;

    let resp = resp.into_inner();
    info!(
        "[HW-CONFIRM] Broadcast response: error_code={}, error_message='{}'",
        resp.error_code, resp.error_message
    );

    if resp.error_code != 0 {
        error!(
            "[HW-CONFIRM] BROADCAST REJECTED: code={}, msg={}",
            resp.error_code, resp.error_message
        );
        return Err(anyhow::anyhow!(
            "Broadcast rejected: {} (code {})",
            resp.error_message,
            resp.error_code
        ));
    }

    info!("[HW-CONFIRM] ====== confirm_send_hw SUCCESS txid={} ======", txid);
    Ok(txid.to_string())
}

/// Export the full viewing key from a connected hardware device.
///
/// This is used during initial pairing: the FVK is imported into the wallet
/// as a watch-only account so the app can derive addresses and scan the chain.
pub fn export_fvk_from_device<S: HardwareSigner>(
    mut signer: S,
) -> Result<zcash_hw_signer_sdk::ExportedFvk> {
    info!("[HW] Requesting FVK export from hardware device...");
    let fvk = signer.export_fvk().map_err(|e| {
        error!("[HW] FVK export failed: {:?}", e);
        anyhow::anyhow!("FVK export failed: {:?}", e)
    })?;
    info!("[HW] FVK exported: ak={}, nk={}", hex::encode(&fvk.ak), hex::encode(&fvk.nk));
    Ok(fvk)
}
