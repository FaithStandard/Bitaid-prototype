//! Leaf scripts used by the funding, bond and buffer outputs.
use bitcoin::opcodes::all::{
    OP_CHECKSIG, OP_CHECKSIGADD, OP_CHECKSIGVERIFY, OP_CLTV, OP_CSV, OP_DROP, OP_NUMEQUALVERIFY,
};
use bitcoin::script::{Builder, ScriptBuf};
use bitcoin::XOnlyPublicKey;

/// x-coordinate of the BIP341 "nothing up my sleeve" point H, used as the internal key of
/// outputs that must have no key path.
pub const NUMS_X: [u8; 32] = [
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
];

pub fn nums() -> XOnlyPublicKey {
    XOnlyPublicKey::from_slice(&NUMS_X).expect("NUMS is a valid x-only key")
}

/// Two keys must sign: `<a> OP_CHECKSIGVERIFY <b> OP_CHECKSIG`. Witness: `[sig_b, sig_a, script, control]`.
pub fn two_keys(a: &XOnlyPublicKey, b: &XOnlyPublicKey) -> ScriptBuf {
    Builder::new()
        .push_x_only_key(a)
        .push_opcode(OP_CHECKSIGVERIFY)
        .push_x_only_key(b)
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

/// A key policy for a scoped key held on several devices: `threshold` of `devices` must sign.
/// One device with threshold 1 is the plain scoped key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyPolicy {
    pub devices: Vec<XOnlyPublicKey>,
    pub threshold: usize,
}

impl KeyPolicy {
    pub fn single(k: XOnlyPublicKey) -> Self {
        KeyPolicy {
            devices: vec![k],
            threshold: 1,
        }
    }
    pub fn of(threshold: usize, devices: Vec<XOnlyPublicKey>) -> Self {
        assert!(threshold >= 1 && threshold <= devices.len());
        KeyPolicy { devices, threshold }
    }
}

/// `threshold` of the device keys, then a second party (the oracle):
/// `<d1> CHECKSIG <d2> CHECKSIGADD … <t> NUMEQUALVERIFY <b> CHECKSIG`.
/// Witness (bottom to top): `[sig_b, sig_dn or empty, …, sig_d1 or empty, script, control]`.
/// A single device with threshold 1 gives the same script as [`two_keys`].
pub fn policy_and(p: &KeyPolicy, b: &XOnlyPublicKey) -> ScriptBuf {
    if p.devices.len() == 1 {
        return two_keys(&p.devices[0], b);
    }
    let mut s = Builder::new()
        .push_x_only_key(&p.devices[0])
        .push_opcode(OP_CHECKSIG);
    for d in &p.devices[1..] {
        s = s.push_x_only_key(d).push_opcode(OP_CHECKSIGADD);
    }
    s.push_int(p.threshold as i64)
        .push_opcode(OP_NUMEQUALVERIFY)
        .push_x_only_key(b)
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

/// One key after an absolute height: `<h> OP_CLTV OP_DROP <x> OP_CHECKSIG`.
pub fn after_height(height: u32, x: &XOnlyPublicKey) -> ScriptBuf {
    Builder::new()
        .push_int(height as i64)
        .push_opcode(OP_CLTV)
        .push_opcode(OP_DROP)
        .push_x_only_key(x)
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

/// One key after a relative timelock (BIP68/112): `<n> OP_CSV OP_DROP <x> OP_CHECKSIG`.
/// `n` is a raw BIP68 value: a block count below 65,536, or `(1 << 22) | units` for 512-second units
/// (one year on Liquid, whose block count would not fit, is `(1 << 22) | 61_594`).
pub fn after_relative(n: u32, x: &XOnlyPublicKey) -> ScriptBuf {
    Builder::new()
        .push_int(n as i64)
        .push_opcode(OP_CSV)
        .push_opcode(OP_DROP)
        .push_x_only_key(x)
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

/// Pay-to-anchor output script (`OP_1 <0x4e73>`), for zero-fee version-3 transactions.
pub fn p2a() -> ScriptBuf {
    ScriptBuf::from_bytes(vec![0x51, 0x02, 0x4e, 0x73])
}
