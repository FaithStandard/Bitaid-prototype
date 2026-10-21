//! Taproot script trees with the leaf layout used throughout Bitaid: leaves are paired left to
//! right, an odd leaf is carried up unpaired, until one root remains. The layout is part of the
//! output's identity, so every implementation must build it the same way.
use bitcoin::secp256k1::{Secp256k1, Verification};
use bitcoin::taproot::{ControlBlock, LeafVersion, TaprootBuilder, TaprootSpendInfo};
use bitcoin::{ScriptBuf, XOnlyPublicKey};

/// Depth of each leaf under the pairing rule.
pub fn leaf_depths(n: usize) -> Vec<u8> {
    let mut depth = vec![0u8; n];
    let mut nodes: Vec<Vec<usize>> = (0..n).map(|i| vec![i]).collect();
    while nodes.len() > 1 {
        let mut next = Vec::new();
        let mut j = 0;
        while j < nodes.len() {
            if j + 1 == nodes.len() {
                next.push(nodes[j].clone());
                j += 1;
                continue;
            }
            let mut merged = nodes[j].clone();
            merged.extend(nodes[j + 1].iter().copied());
            for &i in &merged {
                depth[i] += 1;
            }
            next.push(merged);
            j += 2;
        }
        nodes = next;
    }
    depth
}

/// A taproot output with an internal key and an ordered list of tapscript leaves.
#[derive(Clone, Debug)]
pub struct ScriptTree {
    pub scripts: Vec<ScriptBuf>,
    pub info: TaprootSpendInfo,
}

impl ScriptTree {
    pub fn new<C: Verification>(
        secp: &Secp256k1<C>,
        internal: XOnlyPublicKey,
        scripts: Vec<ScriptBuf>,
    ) -> Self {
        let mut b = TaprootBuilder::new();
        for (s, d) in scripts.iter().zip(leaf_depths(scripts.len())) {
            b = b
                .add_leaf(d, s.clone())
                .expect("pairing layout is a valid DFS order");
        }
        let info = b.finalize(secp, internal).expect("complete tree");
        ScriptTree { scripts, info }
    }
    pub fn script_pubkey(&self) -> ScriptBuf {
        ScriptBuf::new_p2tr_tweaked(self.info.output_key())
    }
    pub fn control(&self, i: usize) -> ControlBlock {
        self.info
            .control_block(&(self.scripts[i].clone(), LeafVersion::TapScript))
            .expect("leaf is in the tree")
    }
}
