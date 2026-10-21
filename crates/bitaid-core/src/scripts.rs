//! Leaf scripts used by the funding, bond and buffer outputs.
use bitcoin::opcodes::all::{OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_CLTV, OP_DROP};
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

/// Pay-to-anchor output script (`OP_1 <0x4e73>`), for zero-fee version-3 transactions.
pub fn p2a() -> ScriptBuf {
    ScriptBuf::from_bytes(vec![0x51, 0x02, 0x4e, 0x73])
}
