// SPDX-License-Identifier: CC0-1.0

//! ltcsuite-compatible PSBT MWEB key types and maps.
//!
//! Key codes match [`ltcsuite/ltcd` `ltcutil/psbt/types.go`](https://github.com/ltcsuite/ltcd/blob/master/ltcutil/psbt/types.go)
//! (first-class `0x90+` types — not BIP174 `0xFC` proprietary blobs).
//!
//! Global kernel fields use `type_value = 0x93` with key
//! `[kernel_index: u32 LE][field_ty: u8][optional pegout_index]`.
//! Parallel pure-MWEB input/output maps (when `unsigned_tx` has no matching vin/vout slots) use
//! global keys: input fields as `type_value = field` with 4-byte index key; output fields as
//! `type_value = 0x94` with 5-byte `[index][field_ty]` key.

mod extract;
mod input;
mod kernel;
mod output;
pub mod types;

use crate::prelude::Vec;

pub use self::extract::assemble_mw_tx;
pub use self::input::MwebInput;
pub use self::kernel::{pegout_coin_from_psbt_value, pegout_psbt_value, MwebKernel};
pub use self::output::MwebOutput;
pub use self::types::*;

pub(crate) fn ensure_index<T: Default>(vec: &mut Vec<T>, index: usize) {
    while vec.len() <= index {
        vec.push(T::default());
    }
}

/// Merge `theirs` into `ours`, pairing maps by `key` (output id, commitment, excess) rather than by
/// position: signers may reorder MWEB inputs and outputs (they are sorted by id when signed), so
/// position alone can pair one input's signature with another's id. A map without the key, or
/// whose key `ours` lacks, falls back to the same position when that slot has no key either;
/// otherwise it is appended.
pub(crate) fn combine_by_key<T: Default, K: PartialEq>(
    ours: &mut Vec<T>,
    theirs: Vec<T>,
    key: impl Fn(&T) -> Option<K>,
    merge: impl Fn(&mut T, T),
) {
    for (i, map) in theirs.into_iter().enumerate() {
        let their_key = key(&map);
        let matched = their_key
            .as_ref()
            .and_then(|k| ours.iter().position(|m| key(m).as_ref() == Some(k)));
        let slot = matched.or_else(|| match ours.get(i) {
            Some(m) if key(m).is_none() => Some(i),
            None if their_key.is_none() => {
                ensure_index(ours, i);
                Some(i)
            }
            _ => None,
        });
        match slot {
            Some(j) => merge(&mut ours[j], map),
            None => ours.push(map),
        }
    }
}

/// Most MWEB inputs a consensus-valid transaction can carry (Core `mw::MAX_NUM_INPUTS`).
pub const MAX_MWEB_PSBT_INPUTS: usize = 50_000;
/// Most MWEB outputs: Core `mw::MAX_BLOCK_WEIGHT` (200,000) over the lightest output (17).
pub const MAX_MWEB_PSBT_OUTPUTS: usize = 200_000 / 17;
/// Most MWEB kernels: Core `mw::MAX_BLOCK_WEIGHT` over the lightest kernel (2).
pub const MAX_MWEB_PSBT_KERNELS: usize = 200_000 / 2;

/// [`ensure_index`] for an index read from an untrusted key: the index sizes an allocation, so
/// anything a valid MWEB transaction cannot reach is refused.
pub(crate) fn ensure_index_bounded<T: Default>(
    vec: &mut Vec<T>,
    index: usize,
    max_len: usize,
) -> Result<(), ()> {
    if index >= max_len {
        return Err(());
    }
    ensure_index(vec, index);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prelude::BTreeMap;
    use crate::psbt::raw;
    use secp256k1::{Secp256k1, SecretKey};

    fn test_pubkey(seed: u8) -> Vec<u8> {
        let sk = SecretKey::from_slice(&[seed; 32]).expect("valid secret");
        sk.public_key(&Secp256k1::new()).serialize().to_vec()
    }

    /// The map index in a global MWEB key sizes an allocation, so an index no valid MWEB
    /// transaction can reach must be refused instead of materialising ~4.3e9 empty maps.
    #[test]
    fn decode_rejects_mweb_map_index_beyond_consensus_limits() {
        use crate::blockdata::transaction::{Transaction, Version};
        use crate::psbt::Psbt;

        let unsigned = Transaction {
            version: Version::TWO,
            lock_time: crate::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
            mw_tx: None,
            is_hog_ex: false,
        };
        let cases = [
            (MWEB_GLOBAL_KERNEL_FIELD_TYPE, MAX_MWEB_PSBT_KERNELS, vec![0x00]),
            (MWEB_GLOBAL_OUTPUT_FIELD_TYPE, MAX_MWEB_PSBT_OUTPUTS, vec![0x00]),
            (MWEB_SPENT_OUTPUT_ID_TYPE, MAX_MWEB_PSBT_INPUTS, vec![]),
        ];
        for (type_value, max, field) in cases {
            for (idx, ok) in [(max as u32 - 1, true), (max as u32, false), (u32::MAX, false)] {
                let mut psbt = Psbt::from_unsigned_tx(unsigned.clone()).unwrap();
                let mut key = idx.to_le_bytes().to_vec();
                key.extend(&field);
                psbt.unknown.insert(raw::Key { type_value, key }, vec![0u8; 32]);
                let decoded = Psbt::deserialize(&psbt.serialize());
                assert_eq!(decoded.is_ok(), ok, "type {type_value:#04x} index {idx}");
            }
        }
    }

    /// Signing sorts MWEB inputs by output id, so combining the funded PSBT with the signed one
    /// must pair maps by id, not by position.
    #[test]
    fn combine_pairs_mweb_inputs_by_output_id() {
        use crate::blockdata::transaction::{Transaction, Version};
        use crate::psbt::Psbt;

        let unsigned = Transaction {
            version: Version::TWO,
            lock_time: crate::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
            mw_tx: None,
            is_hog_ex: false,
        };
        let input = |id: u8, sig: Option<u8>| MwebInput {
            output_id: Some([id; 32]),
            signature: sig.map(|s| vec![s; 64]),
            ..MwebInput::default()
        };
        let mut funded = Psbt::from_unsigned_tx(unsigned.clone()).unwrap();
        funded.mweb_inputs = vec![input(2, None), input(1, None)];
        let mut signed = Psbt::from_unsigned_tx(unsigned).unwrap();
        signed.mweb_inputs = vec![input(1, Some(0x11)), input(2, Some(0x22))];

        funded.combine(signed).unwrap();
        assert_eq!(funded.mweb_inputs.len(), 2);
        for inp in &funded.mweb_inputs {
            let id = inp.output_id.unwrap()[0];
            assert_eq!(inp.signature.as_ref().unwrap()[0], id * 0x11, "input {id}");
        }
    }

    #[test]
    fn type_codes_match_ltcd() {
        assert_eq!(MWEB_TX_OFFSET_TYPE, 0x90);
        assert_eq!(MWEB_TX_STEALTH_OFFSET_TYPE, 0x91);
        assert_eq!(MWEB_KERNEL_COUNT_TYPE, 0x92);
        assert_eq!(MWEB_GLOBAL_KERNEL_FIELD_TYPE, 0x93);
        assert_eq!(MWEB_GLOBAL_OUTPUT_FIELD_TYPE, 0x94);
        assert_eq!(MWEB_SPENT_OUTPUT_ID_TYPE, 0x90);
        assert_eq!(MWEB_STEALTH_ADDRESS_OUTPUT_TYPE, 0x90);
        assert_eq!(MWEB_KERNEL_EXCESS_COMMIT_TYPE, 0);
        assert_eq!(MWEB_KERNEL_SIGNATURE_TYPE, 8);
    }

    #[test]
    fn mweb_input_roundtrip_pairs() {
        let inp = MwebInput {
            output_id: Some([9u8; 32]),
            commit: Some({
                let mut c = [0u8; 33];
                c[0] = 2;
                c
            }),
            amount: Some(50_000),
            address_index: Some(2),
            features: Some(1),
            ..MwebInput::default()
        };
        let back = MwebInput::from_kv_pairs(inp.to_kv_pairs());
        assert_eq!(back.output_id, inp.output_id);
        assert_eq!(back.commit, inp.commit);
        assert_eq!(back.amount, inp.amount);
        assert_eq!(back.address_index, inp.address_index);
        assert_eq!(back.features, inp.features);
    }

    #[test]
    fn mweb_input_key_origin_ltcd_wire() {
        use crate::bip32::{ChildNumber, DerivationPath, Fingerprint};
        use crate::psbt::serialize::{Deserialize, Serialize};

        let sk = SecretKey::from_slice(&[7u8; 32]).unwrap();
        let pk = sk.public_key(&Secp256k1::new());
        let fingerprint = Fingerprint::from([0x11, 0x22, 0x33, 0x44]);
        let path: DerivationPath = vec![
            ChildNumber::from_hardened_idx(0).unwrap(),
            ChildNumber::from_hardened_idx(100).unwrap(),
            ChildNumber::from_hardened_idx(0).unwrap(),
        ]
        .into();
        let ks = (fingerprint, path);

        let inp = MwebInput {
            address_index: Some(3),
            master_scan_key_origin: Some((pk, ks.clone())),
            master_spend_key_origin: Some((pk, {
                let spend_path: DerivationPath = vec![
                    ChildNumber::from_hardened_idx(0).unwrap(),
                    ChildNumber::from_hardened_idx(100).unwrap(),
                    ChildNumber::from_hardened_idx(1).unwrap(),
                ]
                .into();
                (fingerprint, spend_path)
            })),
            ..MwebInput::default()
        };
        inp.validate_key_origins().unwrap();

        let pairs = inp.to_kv_pairs();
        let scan = pairs
            .iter()
            .find(|(ty, _, _)| *ty == MWEB_MASTER_SCAN_KEY_ORIGIN_TYPE)
            .unwrap();
        assert_eq!(scan.1, pk.serialize().to_vec());
        // Value is BIP174 KeySource: fingerprint || LE child indexes
        assert_eq!(scan.2, ks.serialize());
        assert_eq!(
            <(Fingerprint, DerivationPath) as Deserialize>::deserialize(&scan.2).unwrap(),
            ks
        );

        let back = MwebInput::from_kv_pairs(inp.to_kv_pairs());
        assert_eq!(back.master_scan_key_origin, inp.master_scan_key_origin);
        assert_eq!(back.master_spend_key_origin, inp.master_spend_key_origin);
        assert_eq!(back.address_index, Some(3));
    }

    #[test]
    fn type_codes_match_ltcd_origins() {
        assert_eq!(MWEB_MASTER_SCAN_KEY_ORIGIN_TYPE, 0x9A);
        assert_eq!(MWEB_MASTER_SPEND_KEY_ORIGIN_TYPE, 0x9B);
        assert_eq!(MWEB_INPUT_EXTRA_DATA_TYPE, 0x9C);
    }

    #[test]
    fn mweb_input_from_unknown_map() {
        let mut unknown = BTreeMap::new();
        unknown.insert(
            raw::Key {
                type_value: MWEB_SPENT_OUTPUT_ID_TYPE,
                key: Vec::new(),
            },
            [7u8; 32].to_vec(),
        );
        let inp = MwebInput::from_unknown_map(&unknown);
        assert_eq!(inp.output_id, Some([7u8; 32]));
    }

    #[test]
    fn assemble_minimal_mw_tx() {
        let mut commit = [0u8; 33];
        commit[0] = 2;
        let mut excess = [0u8; 33];
        excess[0] = 2;
        excess[1] = 1;

        let inp = MwebInput {
            output_id: Some([1u8; 32]),
            commit: Some(commit),
            output_pubkey: Some(test_pubkey(3)),
            signature: Some(vec![0u8; 64]),
            ..MwebInput::default()
        };
        let out = MwebOutput {
            commit: Some(commit),
            sender_pubkey: Some(test_pubkey(4)),
            output_pubkey: Some(test_pubkey(5)),
            range_proof: Some(vec![0u8; 675]),
            signature: Some(vec![0u8; 64]),
            ..MwebOutput::default()
        };
        let kernel = MwebKernel {
            excess_commit: Some(excess),
            fee: Some(1000),
            features: Some(0x01), // fee bit
            signature: Some([0u8; 64]),
            ..MwebKernel::default()
        };

        let mw = assemble_mw_tx([2u8; 32], [3u8; 32], &[inp], &[out], &[kernel]).unwrap();
        assert_eq!(mw.kernel_offset, [2u8; 32]);
        assert_eq!(mw.stealth_offset, [3u8; 32]);
        assert_eq!(mw.body.inputs.len(), 1);
        assert_eq!(mw.body.outputs.len(), 1);
        assert_eq!(mw.body.kernels.len(), 1);
        assert_eq!(mw.body.kernels[0].fee, Some(1000));
    }

    /// Port of ltcd `TestAllKernelFieldsPopulated` (`partial_kernel_test.go`).
    #[test]
    fn mweb_kernel_all_fields_populated_ltcd_golden() {
        use hex::{test_hex_unwrap as hex, DisplayHex};

        let all_fields_populated = hex!(
            "010021093d957d9c2a301532ffc9c11344e87ad252eccbac597bac6567ba38a2365bea14\
             010121022a969b0465d5e8a24fc0659710925b534e82e81f7677a3012bb8d550dcff9f1c\
             0102081027000000000000010308204e000000000000\
             0204000fa0860100000000000676a9142088ac\
             0204010f80841e00000000000676a9142088ac\
             010504960000000106013f01070a65787472612064617461\
             010840e12804f0a96165fbabeda93782cc0b79e92faab448d72e728dfba7fa82771f0f\
             8195c80e5b8754f01cdf53fca8fe9820b15074d4ae5cfb01b5307c64c51f62cf\
             03fc00010b70726f707269657461727900"
        );

        let pk = MwebKernel::deserialize_ltcd_map(&all_fields_populated).unwrap();

        let expected_excess = hex!(
            "093d957d9c2a301532ffc9c11344e87ad252eccbac597bac6567ba38a2365bea14"
        );
        assert_eq!(pk.excess_commit.as_ref().unwrap().as_slice(), expected_excess.as_slice());

        let expected_stealth = hex!(
            "022a969b0465d5e8a24fc0659710925b534e82e81f7677a3012bb8d550dcff9f1c"
        );
        assert_eq!(pk.stealth_commit.as_ref().unwrap().as_slice(), expected_stealth.as_slice());

        assert_eq!(pk.fee, Some(10_000));
        assert_eq!(pk.pegin_amount, Some(20_000));
        assert_eq!(pk.pegouts.len(), 2);

        let peg0 = pegout_coin_from_psbt_value(&pk.pegouts[0]).unwrap();
        assert_eq!(peg0.amount, 100_000);
        assert_eq!(peg0.script_pub_key.as_bytes(), hex!("76a9142088ac").as_slice());

        let peg1 = pegout_coin_from_psbt_value(&pk.pegouts[1]).unwrap();
        assert_eq!(peg1.amount, 2_000_000);
        assert_eq!(peg1.script_pub_key.as_bytes(), hex!("76a9142088ac").as_slice());

        assert_eq!(pk.lock_height, Some(150));
        assert_eq!(pk.features, Some(0x3f)); // MwebKernelAllFeatureBits
        assert_eq!(pk.extra_data.as_ref().unwrap(), &b"extra data"[..]);

        let expected_sig = hex!(
            "e12804f0a96165fbabeda93782cc0b79e92faab448d72e728dfba7fa82771f0f\
             8195c80e5b8754f01cdf53fca8fe9820b15074d4ae5cfb01b5307c64c51f62cf"
        );
        assert_eq!(pk.signature.as_ref().unwrap().as_slice(), expected_sig.as_slice());

        assert_eq!(pk.unknowns.len(), 1);
        assert_eq!(pk.unknowns[0].0.as_slice(), hex!("fc0001").as_slice());
        assert_eq!(pk.unknowns[0].1, b"proprietary");

        let roundtrip = pk.serialize_ltcd_map();
        assert_eq!(
            roundtrip.as_hex().to_string(),
            all_fields_populated.as_hex().to_string()
        );
    }

    /// §10.6a: finalized MWEB output must keep stealth address through ser/de.
    #[test]
    fn finalized_mweb_output_stealth_address_survives() {
        let scan = test_pubkey(0x21);
        let spend = test_pubkey(0x22);
        let mut stealth = Vec::new();
        stealth.extend_from_slice(&scan);
        stealth.extend_from_slice(&spend);

        let mut commit = [0u8; 33];
        commit[0] = 2;
        commit[1] = 0xab;

        let mut standard = Vec::new();
        standard.extend_from_slice(&test_pubkey(0x30)); // Ke
        standard.push(0x12); // view tag
        standard.extend_from_slice(&0xdeadbeefu64.to_le_bytes());
        standard.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);

        let out = MwebOutput {
            stealth_address: Some(stealth.clone()),
            commit: Some(commit),
            features: Some(1), // standard fields bit
            sender_pubkey: Some(test_pubkey(0x40)),
            output_pubkey: Some(test_pubkey(0x41)),
            standard_fields: Some(standard),
            range_proof: Some(vec![0u8; 64]),
            signature: Some(vec![0x55; 64]),
            ..MwebOutput::default()
        };

        let back = MwebOutput::from_pairs(out.to_pairs());
        assert!(back.signature.is_some());
        assert_eq!(back.stealth_address.as_ref().unwrap(), &stealth);
        assert_eq!(&back.stealth_address.as_ref().unwrap()[..33], &scan[..]);
        assert_eq!(&back.stealth_address.as_ref().unwrap()[33..], &spend[..]);
    }

    /// Unsigned MWEB output stealth address still round-trips.
    #[test]
    fn unsigned_mweb_output_stealth_address_survives() {
        let scan = test_pubkey(0x51);
        let spend = test_pubkey(0x52);
        let mut stealth = Vec::new();
        stealth.extend_from_slice(&scan);
        stealth.extend_from_slice(&spend);

        let out = MwebOutput {
            stealth_address: Some(stealth.clone()),
            ..MwebOutput::default()
        };
        let back = MwebOutput::from_pairs(out.to_pairs());
        assert!(back.signature.is_none());
        assert_eq!(back.stealth_address.as_ref().unwrap(), &stealth);
    }
}
