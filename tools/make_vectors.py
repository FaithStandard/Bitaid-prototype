"""Test vectors from the Python reference (btc.py) for the Rust core: outputs, control blocks,
incident and payout transactions, digests, attestation points, MuSig2 adaptor partial signatures and
completed signatures, all from fixed secrets and nonces."""
import json, hashlib
from btc import *

def sec(label): return b2i(hashlib.sha256(b'bitaid-vector|' + label.encode()).digest()) % (n - 1) + 1
def even(d): return d if has_even_y(point_mul(G, d)) else n - d
P2A = bytes.fromhex('51024e73')
def cs(a, b): return push(a) + bytes([OP_CHECKSIGVERIFY]) + push(b) + bytes([OP_CHECKSIG])
def fb(h, x): return push_num(h) + bytes([OP_CLTV, OP_DROP]) + push(x) + bytes([OP_CHECKSIG])

W, K, I, C = (Key(sec(s)) for s in ('wallet', 'scoped', 'insurer', 'cold'))
X = even(sec('oracle')); XP = point_mul(G, X)
H = 1000
trees = {
 'funding': TapTree(NUMS, [cs(W.x, xonly(XP)), cs(K.x, xonly(XP)), fb(H, W.x)]),
 'bond':    TapTree(NUMS, [cs(K.x, xonly(XP)), cs(C.x, xonly(XP)), fb(H, C.x)]),
 'buffer':  TapTree(NUMS, [cs(K.x, xonly(XP)), cs(I.x, xonly(XP)), fb(H, I.x)]),
}
V = {'secrets': {'wallet': i2b(W.d).hex(), 'scoped': i2b(K.d).hex(), 'insurer': i2b(I.d).hex(), 'cold': i2b(C.d).hex(), 'oracle': i2b(X).hex()},
     'fallback_height': H, 'outputs': {}}
for name, t in trees.items():
    V['outputs'][name] = {'spk': t.spk().hex(), 'controls': [t.control(i).hex() for i in range(3)]}

resp = [Key(sec(f'responder{i}')) for i in range(5)]
signers = [K] + resp; pks = [cbytes(s.P) for s in signers]
ctx = taproot_ctx(pks); ispk = b'\x51\x20' + xonly(ctx['Q'])
V['responders'] = [i2b(r.d).hex() for r in resp]
V['pot_spk'] = ispk.hex()
POTS = [100_000, 600_000, 300_000]; total = sum(POTS)
inc = Tx(version=3); inc.add_in('11' * 32, 0)
for v in POTS: inc.add_out(v, ispk)
inc.add_out(0, P2A)
fspk = trees['funding'].spk()
V['incident'] = {'funding_txid': '11' * 32, 'pots': POTS, 'tx': inc.serialize(False).hex(), 'txid': inc.txid(),
                 'digest_accept_leaf': inc.sighash(0, [(total, fspk)], leaf=trees['funding'].scripts[1]).hex()}
case = 'vector-case'
pay = []
specs = [('deposit', 'returned', 0, [(100_000, 'c0')]),
         ('reward', 'paid (2, 1, 1, 1, 0)', 1, [(240_000, 'r0'), (120_000, 'r1'), (120_000, 'r2'), (120_000, 'r3')]),
         ('bounty', 'split (0, 0, 0, 0, 5)', 2, [(300_000, 'r4')])]
caller_spk = b'\x51\x20' + bytes([0xcc]) * 32
rspk = [b'\x51\x20' + bytes([0xa0 + i]) * 32 for i in range(5)]
def dest(tag): return caller_spk if tag == 'c0' else rspk[int(tag[1])]
for pot, label, vout, outs in specs:
    tx = Tx(version=3); tx.add_in(inc.txid(), vout)
    for v, tag in outs: tx.add_out(v, dest(tag))
    tx.add_out(0, P2A)
    digest = tx.sighash(0, [(POTS[vout], ispk)])
    k = even(sec(f'oracle-nonce|{pot}')); R = point_mul(G, k)
    m = outcome_msg(case, pot, label)
    e = b2i(tagged('BIP0340/challenge', xonly(R) + xonly(XP) + m)) % n
    T = point_add(R, point_mul(XP, e)); att = (k + e * X) % n
    nonces = []
    for j in range(6):
        k1, k2 = sec(f'n1|{pot}|{j}') % n, sec(f'n2|{pot}|{j}') % n
        nonces.append(((k1, k2), (point_mul(G, k1), point_mul(G, k2))))
    agg = nonce_agg([pn for _, pn in nonces])
    parts = [partial_sign(ctx, sn, s.d, pk, agg, digest, T) for (sn, _), s, pk in zip(nonces, signers, pks)]
    pre = partial_agg(ctx, agg, digest, parts, T)
    final = adapt(pre, att)
    assert schnorr_verify(digest, xonly(ctx['Q']), final)
    pay.append({'pot': pot, 'label': label, 'vout': vout, 'outputs': [[v, dest(t).hex()] for v, t in outs],
                'tx': tx.serialize(False).hex(), 'digest': digest.hex(),
                'oracle_nonce': i2b(k).hex(), 'outcome_msg': m.hex(), 'point': cbytes(T).hex(), 'attestation': i2b(att).hex(),
                'nonces': [[i2b(a).hex(), i2b(b).hex()] for (a, b), _ in nonces],
                'partials': [i2b(p).hex() for p in parts], 'presig_rx': pre['rx'].hex(), 'presig_s': i2b(pre['s']).hex(),
                'final_sig': final.hex()})
V['case'] = case; V['payouts'] = pay
json.dump(V, open(__import__('os').path.join(__import__('os').path.dirname(__file__), '..', 'crates', 'bitaid-core', 'tests', 'vectors.json'), 'w'), indent=1)
print('wrote', len(pay), 'payout vectors')
