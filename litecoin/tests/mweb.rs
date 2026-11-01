// SPDX-License-Identifier: CC0-1.0

//! End-to-end tests for Litecoin MimbleWimble (MWEB) parsing.
//!
//! Round-trips real mainnet transactions and blocks against the consensus codec to verify that
//! the wire format implemented in `litecoin::blockdata::mimblewimble` and the MWEB extension on
//! `Block` and `Transaction` matches what Litecoin Core produces.

#![cfg(feature = "std")]

use litecoin::blockdata::mimblewimble::{KernelFeatures, OutputFeatures};
use litecoin::consensus::{deserialize, serialize};
use litecoin::hex::FromHex;
use litecoin::secp256k1::PublicKey;
use litecoin::{
    Block, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, Witness,
};

fn hex_pubkey(s: &str) -> PublicKey {
    let bytes = Vec::<u8>::from_hex(s).expect("hex");
    PublicKey::from_slice(&bytes).expect("pubkey")
}

/// Litecoin mainnet MWEB-bearing transaction (segwit flag 9): pegs out two amounts and creates
/// one MWEB output.
#[test]
fn mweb_transaction_decodes_and_roundtrips() {
    let tx_bytes = Vec::<u8>::from_hex(concat!(
        "0200000000080000011819a9e1c5d2be3ff51d4041b281e355e9fe86e2389f69e79a81d73b32e873f7f056",
        "438d0d702760f98d20c851a7ce32ea9a995f53ebb460ebdb3264634849910101483f1e4f7f9e36824fd61e5",
        "62fc07d48b3451e823d5f6afea4d5d8374b997f7c086b85e49b94ba898bbc8120e9253d3a8b2bf9b465ff7b",
        "8ace694e341a6fd6f18e033d7d91b44bef189813559e734245974b56a73ad6e483fd2f0cfeca9dde4a5c5d0",
        "3db2bb489c1e9ed0104f1c8064766f3999f427eaeb20bebed973e57954cd4a66c0179db7cc9f7a9f83c5173",
        "f129143f478178436fb6ca6bc54076062a4905f8d5a91b04e0bb6af88eacb030323eea73c5678f27f267878",
        "64546a6f4fc92888f350108269e60eeaa812b4e776cf6a6e22b213679021bc1532e7541ccb606b73c254168",
        "020eab5a7b8897be8eeaff91b8899c492a9a39a02d6c0211f97aa7381c78671f850355cdb42339a479bd9b8",
        "506d6bcdc351aa769a5b63cca9b9b1bac9337cd06e27e010236ccd266c02cae55ed3be49fb239154c957149",
        "75a9576eb4dc5e58f7d524b753bb62273ae98ea4405c80b535f6d53702916acc1cc07ab048a62acb5a6bacf",
        "7f6a30d5c4979a17d6b05d9e0fb9040fc74e110fac309c1942d72ea169c65e0cf9bfd7c7ffb406ba2b49b06",
        "2a7705731fde8c7f22cf05d02a20710c20145fc0d90bd6d10283098ecd07bced51df89f586309d8523ca27d",
        "9f26f9b61a5de20e8adcbe2ff4e7b238a6f40f22cf67d0f5b893e07998d2e9778e2f7091e9b10aab174a8d8",
        "ce64eedd90b3a24606c7c69d45eb94ff386c01705adf57f436bcf93048dac2b094c071d38eebf05046a7e63",
        "d033156f0a1a32214d28c426782da2f4f6b19605583e64f54a6c068caa8d14d3edee2221808182919c87ecd",
        "0c7c2f794e4b9db828cfeea6be8974cd93ecb0a0f9ae5d3e949bb15d64c8ed84f0ea8b447856217b42dff7d",
        "9fac4e5a949ed358a1dfd2d330a51acd41df1b7c8f1952143d210258fb925a60fb9b61ea23c6704bdcf3539",
        "4d4d44f8dc2c20f9141c3567bf01ccc1b9232d2aa6fb7969afa36c029bb8230eef3a189664db9524ede6d8a",
        "c00e38686cb26c02c77556b1a1699d695f9300578171b3d8c84a7f2ae2f5de7a147fe3e1fec8bddf52b7843",
        "ae1b1f7d5ec372869496d4932060a978cb1d92c273002230f10fba5a8d086ca7681710bb955e77c8f87b71e",
        "90af2caa5d94e406e928925f76eb22663d8ce24af4d5af8cc6bcf62652327a129d6a6e51e7da944aeead34b",
        "2449965b792730aeb8d6e32b970f83b17fbb3cbc2d144490784e55e53e8912d8ea85d6e5f5046ebe6aa407e",
        "325ac3291a091f446d2ac63d9ab28382584b95856d641f5ae6fcca92b8ff1bc328b63995280ab66bd598dab",
        "66abac17691906e910ab8c2e35e8d34118ca9c2556cb9d2e9afab98f4f98d449b8ed3dd733d11ea0bfb31b5",
        "5d35750d2bd22f123025b7ad7f9194cee14a11a617da84c067b5bc273c4c8a9f5ff42f5db9de68a2567bb1f",
        "1b5a522a2f5d9dcd80ffbd8396f7965b2aade9bbf12d918740c27c64dda7df2113d65fbb9710e77dd1ecd9c",
        "7bb9eb4bd5bf01d301f905a562a7cd7c9b967b405882511d1acde3457d22918f57e64f58fdb01159a540282",
        "dbea9300160014cfc8a91900d66314f40d54fe85b55e27cd2c505a80edb4c900160014eac5b26e7ac2eb063",
        "d216328e890a75eb7e446de021a6c99c8996aef706e13f6cced269369f73974ff283d46a4f31663952add67",
        "650940e5f34a5a341457ac8b197e0205df71510c0e0c0c317b584d3377ac1e4b0a185a460c2501617c413df",
        "db3a131dbd4c3904d43a66f7cd62f9596f6df5a49d76efdac29f967f0b4763aa6f5f9078a9ee5e38c9ae1b8",
        "cd558b4c49b32c31d7474c00000000",
    ))
    .expect("hex");

    let tx: Transaction = deserialize(&tx_bytes).expect("decode mweb tx");
    assert_eq!(tx.version.0, 2);
    assert!(!tx.is_hog_ex, "MWEB-with-body tx is not a HogEx");

    let mw = tx.mw_tx.as_ref().expect("MWEB body present");
    assert_eq!(
        mw.kernel_offset,
        <[u8; 32]>::from_hex("1819a9e1c5d2be3ff51d4041b281e355e9fe86e2389f69e79a81d73b32e873f7")
            .unwrap()
    );
    assert_eq!(
        mw.stealth_offset,
        <[u8; 32]>::from_hex("f056438d0d702760f98d20c851a7ce32ea9a995f53ebb460ebdb326463484991")
            .unwrap()
    );

    // Input.
    assert_eq!(mw.body.inputs.len(), 1);
    let input = &mw.body.inputs[0];
    assert_eq!(input.features, 1);
    assert_eq!(
        input.input_public_key,
        Some(hex_pubkey("03db2bb489c1e9ed0104f1c8064766f3999f427eaeb20bebed973e57954cd4a66c"))
    );
    assert_eq!(
        input.output_public_key,
        hex_pubkey("033d7d91b44bef189813559e734245974b56a73ad6e483fd2f0cfeca9dde4a5c5d")
    );

    // Output.
    assert_eq!(mw.body.outputs.len(), 1);
    let output = &mw.body.outputs[0];
    assert_eq!(output.message.features, OutputFeatures::StandardFieldsFeatureBit as u8);
    let std_fields = output.message.standard_fields.as_ref().expect("standard fields");
    assert_eq!(std_fields.view_tag, 187);
    assert_eq!(std_fields.masked_value, 6_647_493_983_704_065_890);

    // Kernel with fee + stealth excess + pegouts (features = 0x15).
    assert_eq!(mw.body.kernels.len(), 1);
    let kernel = &mw.body.kernels[0];
    let expected_features = KernelFeatures::FeeFeatureBit as u8
        | KernelFeatures::PegoutFeatureBit as u8
        | KernelFeatures::StealthExcessFeatureBit as u8;
    assert_eq!(kernel.features, expected_features);
    assert_eq!(kernel.fee, Some(3540));
    assert_eq!(kernel.pegin, None);
    assert_eq!(kernel.pegouts.len(), 2);
    assert_eq!(kernel.pegouts[0].amount, 1_000_000_000);
    assert_eq!(
        kernel.pegouts[0].script_pub_key.as_bytes(),
        &<Vec<u8>>::from_hex("0014cfc8a91900d66314f40d54fe85b55e27cd2c505a").unwrap()[..]
    );
    assert_eq!(kernel.pegouts[1].amount, 500_000_000);

    // Round-trip: re-encoding should reproduce the exact wire format.
    assert_eq!(serialize(&tx), tx_bytes, "MWEB tx round-trip mismatch");
}

/// Litecoin regtest block at MW chain height 435 containing a HogEx transaction and an embedded
/// MWEB extension block with one peg-in kernel and one output.
#[test]
fn hogex_block_decodes_and_roundtrips() {
    let block_bytes =
        Vec::<u8>::from_hex(include_str!("data/hogex_block.txt").trim()).expect("hex");

    let block: Block = deserialize(&block_bytes).expect("decode hogex block");

    // 3 txs: coinbase, MWEB peg-in tx, HogEx.
    assert_eq!(block.txdata.len(), 3);
    assert!(!block.txdata[0].is_hog_ex);
    assert!(!block.txdata[1].is_hog_ex);
    assert!(block.txdata[2].is_hog_ex, "last tx must be HogEx");
    assert_eq!(block.header.time, 1_706_812_942);

    let mw = block.mweb_block.as_ref().expect("MWEB block present");
    assert_eq!(mw.header.height, 435);
    assert_eq!(mw.header.output_mmr_size, 2);
    assert_eq!(mw.header.kernel_mmr_size, 1);
    assert_eq!(
        mw.header.kernel_offset,
        <[u8; 32]>::from_hex("9e984f060b4233e1a34afb44ae006ffd7ade9abb05b3c78dad8029d696bf72f7")
            .unwrap()
    );
    assert_eq!(
        mw.header.stealth_offset,
        <[u8; 32]>::from_hex("c0ecbf5563ed14f264fda787033cc5f5270d8c17e49633b98c11908cdabf282d")
            .unwrap()
    );

    // Peg-in kernel (features 0x13 = Fee | Pegin | StealthExcess).
    assert_eq!(mw.tx_body.inputs.len(), 0);
    assert_eq!(mw.tx_body.outputs.len(), 1);
    assert_eq!(mw.tx_body.kernels.len(), 1);
    let kernel = &mw.tx_body.kernels[0];
    let expected_features = KernelFeatures::FeeFeatureBit as u8
        | KernelFeatures::PeginFeatureBit as u8
        | KernelFeatures::StealthExcessFeatureBit as u8;
    assert_eq!(kernel.features, expected_features);
    assert_eq!(kernel.fee, Some(2100));
    assert_eq!(kernel.pegin, Some(1_000_002_100));

    // Output.
    let output = &mw.tx_body.outputs[0];
    assert_eq!(output.message.features, OutputFeatures::StandardFieldsFeatureBit as u8);
    let std_fields = output.message.standard_fields.as_ref().expect("standard fields");
    assert_eq!(std_fields.view_tag, 156);
    assert_eq!(std_fields.masked_value, 5_350_801_249_539_001_306);
    assert_eq!(
        output.receiver_key().unwrap(),
        hex_pubkey("0333c3e2213250cfa1741083d6ebfbcdbe40008fc8c6a58ca4234adf77bb484458")
    );

    // Full round-trip.
    assert_eq!(serialize(&block), block_bytes, "block round-trip mismatch");
}

/// Core reads the MWEB extension block whenever the last transaction is a HogEx; the header
/// version bit 29 plays no part, and `0x40000000` is a valid block version. The same mainnet block
/// with that version must still decode its extension block and round-trip.
#[test]
fn hogex_block_without_version_bit_29_decodes() {
    let mut block_bytes =
        Vec::<u8>::from_hex(include_str!("data/hogex_block.txt").trim()).expect("hex");
    let original: Block = deserialize(&block_bytes).expect("decode hogex block");
    block_bytes[..4].copy_from_slice(&0x4000_0000i32.to_le_bytes());

    let block: Block = deserialize(&block_bytes).expect("decode block with bit 29 clear");
    assert_eq!(block.header.version.to_consensus(), 0x4000_0000);
    assert_eq!(block.mweb_block, original.mweb_block);
    assert!(block.mweb_block.is_some());
    assert_eq!(serialize(&block), block_bytes);
}

/// Synthesizes a transaction carrying BOTH a witness input and an MWEB body, exercising the
/// extended segwit flag byte `0x09 = FLAGS_SEGWIT | FLAGS_MWEB_TX`. Round-trips it through the
/// consensus codec to prove the flag-9 path encodes and decodes symmetrically.
#[test]
fn mweb_transaction_flag9_witness_plus_body_roundtrips() {
    // Start from the real mainnet flag-8 MWEB tx fixture; reuse its MWEB body verbatim.
    let base_bytes = Vec::<u8>::from_hex(concat!(
        "0200000000080000011819a9e1c5d2be3ff51d4041b281e355e9fe86e2389f69e79a81d73b32e873f7f056",
        "438d0d702760f98d20c851a7ce32ea9a995f53ebb460ebdb3264634849910101483f1e4f7f9e36824fd61e5",
        "62fc07d48b3451e823d5f6afea4d5d8374b997f7c086b85e49b94ba898bbc8120e9253d3a8b2bf9b465ff7b",
        "8ace694e341a6fd6f18e033d7d91b44bef189813559e734245974b56a73ad6e483fd2f0cfeca9dde4a5c5d0",
        "3db2bb489c1e9ed0104f1c8064766f3999f427eaeb20bebed973e57954cd4a66c0179db7cc9f7a9f83c5173",
        "f129143f478178436fb6ca6bc54076062a4905f8d5a91b04e0bb6af88eacb030323eea73c5678f27f267878",
        "64546a6f4fc92888f350108269e60eeaa812b4e776cf6a6e22b213679021bc1532e7541ccb606b73c254168",
        "020eab5a7b8897be8eeaff91b8899c492a9a39a02d6c0211f97aa7381c78671f850355cdb42339a479bd9b8",
        "506d6bcdc351aa769a5b63cca9b9b1bac9337cd06e27e010236ccd266c02cae55ed3be49fb239154c957149",
        "75a9576eb4dc5e58f7d524b753bb62273ae98ea4405c80b535f6d53702916acc1cc07ab048a62acb5a6bacf",
        "7f6a30d5c4979a17d6b05d9e0fb9040fc74e110fac309c1942d72ea169c65e0cf9bfd7c7ffb406ba2b49b06",
        "2a7705731fde8c7f22cf05d02a20710c20145fc0d90bd6d10283098ecd07bced51df89f586309d8523ca27d",
        "9f26f9b61a5de20e8adcbe2ff4e7b238a6f40f22cf67d0f5b893e07998d2e9778e2f7091e9b10aab174a8d8",
        "ce64eedd90b3a24606c7c69d45eb94ff386c01705adf57f436bcf93048dac2b094c071d38eebf05046a7e63",
        "d033156f0a1a32214d28c426782da2f4f6b19605583e64f54a6c068caa8d14d3edee2221808182919c87ecd",
        "0c7c2f794e4b9db828cfeea6be8974cd93ecb0a0f9ae5d3e949bb15d64c8ed84f0ea8b447856217b42dff7d",
        "9fac4e5a949ed358a1dfd2d330a51acd41df1b7c8f1952143d210258fb925a60fb9b61ea23c6704bdcf3539",
        "4d4d44f8dc2c20f9141c3567bf01ccc1b9232d2aa6fb7969afa36c029bb8230eef3a189664db9524ede6d8a",
        "c00e38686cb26c02c77556b1a1699d695f9300578171b3d8c84a7f2ae2f5de7a147fe3e1fec8bddf52b7843",
        "ae1b1f7d5ec372869496d4932060a978cb1d92c273002230f10fba5a8d086ca7681710bb955e77c8f87b71e",
        "90af2caa5d94e406e928925f76eb22663d8ce24af4d5af8cc6bcf62652327a129d6a6e51e7da944aeead34b",
        "2449965b792730aeb8d6e32b970f83b17fbb3cbc2d144490784e55e53e8912d8ea85d6e5f5046ebe6aa407e",
        "325ac3291a091f446d2ac63d9ab28382584b95856d641f5ae6fcca92b8ff1bc328b63995280ab66bd598dab",
        "66abac17691906e910ab8c2e35e8d34118ca9c2556cb9d2e9afab98f4f98d449b8ed3dd733d11ea0bfb31b5",
        "5d35750d2bd22f123025b7ad7f9194cee14a11a617da84c067b5bc273c4c8a9f5ff42f5db9de68a2567bb1f",
        "1b5a522a2f5d9dcd80ffbd8396f7965b2aade9bbf12d918740c27c64dda7df2113d65fbb9710e77dd1ecd9c",
        "7bb9eb4bd5bf01d301f905a562a7cd7c9b967b405882511d1acde3457d22918f57e64f58fdb01159a540282",
        "dbea9300160014cfc8a91900d66314f40d54fe85b55e27cd2c505a80edb4c900160014eac5b26e7ac2eb063",
        "d216328e890a75eb7e446de021a6c99c8996aef706e13f6cced269369f73974ff283d46a4f31663952add67",
        "650940e5f34a5a341457ac8b197e0205df71510c0e0c0c317b584d3377ac1e4b0a185a460c2501617c413df",
        "db3a131dbd4c3904d43a66f7cd62f9596f6df5a49d76efdac29f967f0b4763aa6f5f9078a9ee5e38c9ae1b8",
        "cd558b4c49b32c31d7474c00000000",
    ))
    .expect("hex");
    let mut tx: Transaction = deserialize(&base_bytes).expect("decode base mweb tx");

    // Promote to flag-9 by attaching a single segwit input with a witness stack.
    tx.input.push(TxIn {
        previous_output: OutPoint::null(),
        script_sig: ScriptBuf::new(),
        sequence: Sequence::MAX,
        witness: Witness::from_slice(&[&[0xdeu8, 0xad, 0xbe, 0xef][..]]),
    });

    let encoded = serialize(&tx);

    // Version is 4 bytes, marker is 1 byte → flag byte sits at offset 5.
    assert_eq!(encoded[4], 0x00, "BIP-141 marker");
    assert_eq!(encoded[5], 0x09, "extended segwit flag for witness + MWEB body");

    let decoded: Transaction = deserialize(&encoded).expect("decode flag-9 tx");
    assert_eq!(decoded.input.len(), 1);
    assert!(!decoded.input[0].witness.is_empty());
    assert!(decoded.mw_tx.is_some(), "MWEB body preserved");
    assert!(!decoded.is_hog_ex);
    assert_eq!(serialize(&decoded), encoded, "flag-9 round-trip mismatch");
}

/// Regression: a real Litecoin mainnet block (#2644351) that previously panicked while parsing
/// the MWEB extension. Simply requires that decode + encode round-trip without crashing.
#[test]
fn regression_block_2644351_parses() {
    let block_bytes =
        Vec::<u8>::from_hex(include_str!("data/block_2644351.txt").trim()).expect("hex");
    let block: Block = deserialize(&block_bytes).expect("decode block 2644351");
    assert!(!block.txdata.is_empty());
    assert_eq!(serialize(&block), block_bytes);
}
