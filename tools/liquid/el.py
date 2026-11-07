"""Elements (Liquid) variants of the Bitaid test primitives.

Differences from Bitcoin that matter for the escrows (Elements doc/taproot-sighash.mediawiki):
  - taproot tags are suffixed "/elements" (TapLeaf, TapBranch, TapTweak, TapSighash) and the
    tapscript leaf version is 0xc4;
  - the signature message drops the epoch byte, starts with the genesis hash twice, and commits to
    outpoint flags, the spent outputs' assets and amounts, issuances and output witnesses;
  - transactions carry an asset and an explicit or confidential value per output, and the fee is an
    explicit output with an empty scriptPubKey;
  - Elements 23 has no version-3/TRUC, pay-to-anchor or package relay, so pre-signed transactions
    carry their fee themselves (Liquid fees are near-constant: 0.1 sat/vB minimum, one-minute blocks).
"""
import json, subprocess, struct, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))   # tools/btc.py
import btc
from btc import *

_orig_tagged = btc.tagged
def _tagged(tag, msg):
    if tag in ('TapLeaf', 'TapBranch', 'TapTweak', 'TapSighash'): tag += '/elements'
    return _orig_tagged(tag, msg)
btc.tagged = _tagged
tagged = _tagged
LEAF = 0xc4
def _leaf_hash(script): return _tagged('TapLeaf', bytes([LEAF]) + ser_compact(len(script)) + script)
btc.leaf_hash = _leaf_hash
leaf_hash = _leaf_hash
def _control(self, i):
    return bytes([LEAF | (0 if has_even_y(self.Q) else 1)]) + xonly(self.internal) + b''.join(self.paths[i])
btc.TapTree.control = _control

import time
# the node: ECLI is the elements-cli command line (default: a local elementsregtest node);
# CHAIN=liquidtestnet runs against the real Liquid testnet, waiting for its one-minute blocks
CHAIN = os.environ.get('CHAIN', 'elementsregtest')
ECLI = os.environ.get('ECLI', '/home/claude/nodes/elements-23.3.4/bin/elements-cli -chain=elementsregtest '
                      '-datadir=/home/claude/nodes/el -rpcuser=u -rpcpassword=p -rpcport=18884').split()
REGTEST = CHAIN == 'elementsregtest'
HRP = os.environ.get('HRP') or {'elementsregtest': 'ert', 'liquidtestnet': 'tex', 'liquidv1': 'ex'}[CHAIN]
if CHAIN == 'liquidv1':
    sys.exit('refusing to run on Liquid mainnet: test chains only')
EL = btc.Node(ECLI)
ASSET = bytes.fromhex(EL('getsidechaininfo')['pegged_asset'])[::-1]       # serialized byte order
GENESIS = bytes.fromhex(EL('getblockhash', 0))[::-1]

def eval_(v): return b'\x01' + struct.pack('>Q', v)                        # explicit value
def easset(): return b'\x01' + ASSET

class ETx:
    """Elements transaction with explicit assets and values, no issuances or pegins."""
    def __init__(self, version=2, locktime=0):
        self.version = version; self.locktime = locktime; self.vin = []; self.vout = []
    def add_in(self, txid, vout, seq=0xfffffffd):
        self.vin.append({'txid': txid, 'vout': vout, 'seq': seq, 'wit': []})
    def add_out(self, value, spk): self.vout.append((value, spk))
    def add_fee(self, value): self.vout.append((value, b''))
    def _out(self, v, s): return easset() + eval_(v) + b'\x00' + ser_compact(len(s)) + s
    def _outs(self): return b''.join(self._out(v, s) for v, s in self.vout)
    def serialize(self, witness=True):
        has_w = witness and any(i['wit'] for i in self.vin)
        b = struct.pack('<i', self.version) + bytes([1 if has_w else 0])
        b += ser_compact(len(self.vin))
        for i in self.vin:
            b += bytes.fromhex(i['txid'])[::-1] + struct.pack('<I', i['vout']) + b'\x00' + struct.pack('<I', i['seq'])
        b += ser_compact(len(self.vout)) + self._outs() + struct.pack('<I', self.locktime)
        if has_w:
            for i in self.vin:   # issuance amount rangeproof, inflation keys rangeproof, script witness, pegin witness
                b += b'\x00' + b'\x00' + ser_compact(len(i['wit'])) + b''.join(ser_compact(len(w)) + w for w in i['wit']) + b'\x00'
            for _ in self.vout:  # surjection proof, rangeproof
                b += b'\x00' + b'\x00'
        return b
    def hex(self): return self.serialize().hex()
    def txid(self): return sha256(sha256(self.serialize(False)))[::-1].hex()
    def sighash(self, idx, prevouts, leaf=None):
        """prevouts: list of (value, spk). SIGHASH_DEFAULT, no annex."""
        m = GENESIS + GENESIS + b'\x00' + struct.pack('<i', self.version) + struct.pack('<I', self.locktime)
        m += sha256(b'\x00' * len(self.vin))                                              # outpoint flags
        m += sha256(b''.join(bytes.fromhex(i['txid'])[::-1] + struct.pack('<I', i['vout']) for i in self.vin))
        m += sha256(b''.join(easset() + eval_(v) for v, _ in prevouts))                   # spent assets and amounts
        m += sha256(b''.join(ser_compact(len(s)) + s for _, s in prevouts))
        m += sha256(b''.join(struct.pack('<I', i['seq']) for i in self.vin))
        m += sha256(b'\x00' * len(self.vin))                                              # issuances
        m += sha256(b'\x00\x00' * len(self.vin))                                          # issuance rangeproofs
        m += sha256(self._outs())
        m += sha256(b'\x00\x00' * len(self.vout))                                         # output witnesses
        m += bytes([2 if leaf is not None else 0]) + struct.pack('<I', idx)
        if leaf is not None:
            m += leaf_hash(leaf) + b'\x00' + b'\xff\xff\xff\xff'
        return _tagged('TapSighash', m)

# bech32m with the elementsregtest prefix, for unconfidential taproot addresses
CH = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
def _pm(v):
    g = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]; c = 1
    for x in v:
        b = c >> 25; c = (c & 0x1ffffff) << 5 ^ x
        for i in range(5): c ^= g[i] if (b >> i) & 1 else 0
    return c
def _cv(data, f, t):
    acc = bits = 0; out = []
    for x in data:
        acc = (acc << f) | x; bits += f
        while bits >= t: bits -= t; out.append((acc >> bits) & ((1 << t) - 1))
    if bits: out.append((acc << (t - bits)) & ((1 << t) - 1))
    return out
def addr(spk, hrp=HRP):
    d = [1] + _cv(spk[2:], 8, 5); hx = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    chk = _pm(hx + d + [0] * 6) ^ 0x2bc830a3
    return hrp + '1' + ''.join(CH[x] for x in d + [(chk >> 5 * (5 - i)) & 31 for i in range(6)])

_MINE = None
_SENT = []
def emine(k=1):
    """regtest: mine k blocks. Liquid testnet: wait for k new blocks (about a minute each) and for
    everything this test has broadcast to confirm."""
    global _MINE
    if REGTEST:
        if _MINE is None: _MINE = EL('getaddressinfo', EL('getnewaddress', wallet='w'), wallet='w')['unconfidential']
        return EL('generatetoaddress', k, _MINE)
    target = EL('getblockcount') + k
    t0 = time.time()
    while EL('getblockcount') < target or any(_unconfirmed(t) for t in _SENT):
        if time.time() - t0 > 60 * (k + 20):
            raise RuntimeError(f'waited {int(time.time() - t0)} s for block {target} and confirmations')
        time.sleep(5)
    _SENT.clear()
def _unconfirmed(txid):
    try:
        return EL('getmempoolentry', txid) is not None
    except btc.RPCError:
        return False
def efund(spk, sats):
    txid = EL('sendtoaddress', addr(spk), round(sats / 1e8, 8), wallet='w')
    _SENT.append(txid)
    dec = EL('gettransaction', txid, 'true', 'true', wallet='w')['decoded']
    vout = next(o['n'] for o in dec['vout'] if o['scriptPubKey']['hex'] == spk.hex())
    emine(1); return txid, vout
def etry(tx):
    r = EL('testmempoolaccept', [tx.hex()])[0]
    if not r['allowed']: return False, r.get('reject-reason', '?')
    _SENT.append(EL('sendrawtransaction', tx.hex())); return True, 'accepted'
def eaddr_spk():
    a = EL('getaddressinfo', EL('getnewaddress', wallet='w'), wallet='w')
    return bytes.fromhex(a['scriptPubKey'])
