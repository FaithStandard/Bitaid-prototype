"""Test 18 — the escrows on Liquid (Elements 23.3.4, elementsregtest), explicit assets and amounts.

The same constructions as tests 1–6 and 15, adapted to Elements: "/elements" taproot tags and leaf
version 0xc4, the Elements signature message, explicit fee outputs. Elements 23 has no version-3
package relay or pay-to-anchor, so every pre-signed transaction carries its own fee, fixed when it is
signed; on Liquid that is workable because fees are near-constant (0.1 sat/vB minimum, blocks every
minute). Timelocks: Liquid blocks come every minute, so a 365-day fallback is 525,600 blocks, ten
times Bitcoin's count; tested here with short heights.
"""
import random
from el import *
from threshold import *
import os

results = []
def check(name, ok, detail=''):
    st = 'PASS' if ok else 'FAIL'; results.append((st, name, detail)); print(f'[{st}] {name}' + (f' — {detail}' if detail else ''))
FEE = 1000
def cs(a_x, b_x): return push(a_x) + bytes([OP_CHECKSIGVERIFY]) + push(b_x) + bytes([OP_CHECKSIG])
def cltv(h, x): return push_num(h) + bytes([OP_CLTV, OP_DROP]) + push(x) + bytes([OP_CHECKSIG])

pool = Pool(21, batch=8)
CASE = 'case-liquid'
# SCALE divides the pots (faucet coins on Liquid testnet: SCALE=10 needs about 0.0011 L-BTC in all)
SCALE = int(os.environ.get('SCALE', '1'))
POTS = {k: v // SCALE for k, v in {'deposit': 100_000, 'reward': 600_000, 'bounty': 300_000}.items()}

# ---------------------------------------------------------------- 1. funding output
W, K = Key(), Key()
fb_h = EL('getblockcount') + 30
ftree = TapTree(NUMS, [cs(W.x, xonly(pool.P)), cs(K.x, xonly(pool.P)), cltv(fb_h, W.x)])
total = sum(POTS.values()) + FEE
ftxid, fvout = efund(ftree.spk(), total)
dest = eaddr_spk()

steal = ETx(); steal.add_in(ftxid, fvout); steal.add_out(total - FEE, dest); steal.add_fee(FEE)
m = steal.sighash(0, [(total, ftree.spk())], leaf=ftree.scripts[1])
steal.vin[0]['wit'] = [schnorr_sign(m, K.d), schnorr_sign(m, K.d), ftree.scripts[1], ftree.control(1)]
check('Funding output: the scoped key alone cannot move it', not etry(steal)[0])
early = ETx(locktime=fb_h); early.vin = []; early.add_in(ftxid, fvout, seq=0xfffffffe); early.add_out(total - FEE, dest); early.add_fee(FEE)
m = early.sighash(0, [(total, ftree.spk())], leaf=ftree.scripts[2])
early.vin[0]['wit'] = [schnorr_sign(m, W.d), ftree.scripts[2], ftree.control(2)]
check('Funding output: the wallet-alone fallback is refused before its height', not etry(early)[0])

# ---------------------------------------------------------------- 2. acceptance
responders = [Key() for _ in range(3)]; ra = [eaddr_spk() for _ in responders]
signers = [K] + responders; pks = [cbytes(s.P) for s in signers]
ctx = taproot_ctx(pks); ispk = b'\x51\x20' + xonly(ctx['Q'])
def musig(msg, T_=None):
    nonces = [nonce_gen() for _ in signers]; agg = nonce_agg([pn for _, pn in nonces])
    return partial_agg(ctx, agg, msg, [partial_sign(ctx, sn, s.d, pk, agg, msg, T_) for (sn, _), s, pk in zip(nonces, signers, pks)], T_)
inc = ETx(); inc.add_in(ftxid, fvout)
for v in POTS.values(): inc.add_out(v, ispk)
inc.add_fee(FEE)
m = inc.sighash(0, [(total, ftree.spk())], leaf=ftree.scripts[1])
co = pool.frost_sign(m, random.sample(range(1, 22), 11))
inc.vin[0]['wit'] = [co, schnorr_sign(m, K.d), ftree.scripts[1], ftree.control(1)]
outs = {pot: (inc.txid(), i, v) for i, (pot, v) in enumerate(POTS.items())}
ok, why = etry(inc); emine(1)
check('Incident transaction: scoped key + 11-of-21 FROST co-signature, three MuSig2 pot outputs, fee output', ok, why)

# ---------------------------------------------------------------- 3. pre-signed payouts with their own fee
NON = {'deposit': 0, 'reward': 1, 'bounty': 2}
def split(v, sh): return [((v - FEE) * a // 100, ra[i]) for i, a in enumerate(sh) if a]
endings = {'deposit': {'returned': [(POTS['deposit'] - FEE, dest)], 'seized 60/40/0': split(POTS['deposit'], (60, 40, 0))},
           'reward': {'not achieved': [(POTS['reward'] - FEE, dest)], **{f'paid {a}/{b}/{c}': split(POTS['reward'], (a, b, c)) for a, b, c in [(100, 0, 0), (60, 30, 10)]}}}
pre = {}
for pot, ends in endings.items():
    txid, vout, v = outs[pot]
    for label, payto in ends.items():
        tx = ETx(); tx.add_in(txid, vout)
        for amt, s in payto: tx.add_out(amt, s)
        paid = sum(a for a, _ in payto); tx.add_fee(v - paid)
        pre[(pot, label)] = (tx, musig(tx.sighash(0, [(v, ispk)]), pool.point(NON[pot], outcome_msg(CASE, pot, label))))
# bounty in the sliced layout: a fan-out into 3 slices, each paid to one seat
T = 3; txid, vout, v = outs['bounty']; sv = (v - FEE) // T
fan = ETx(); fan.add_in(txid, vout)
for j in range(T): fan.add_out(sv, ispk)
fan.add_fee(v - sv * T)
p = musig(fan.sighash(0, [(v, ispk)])); fan.vin[0]['wit'] = [p['rx'] + i2b(p['s'])]
pool2 = Pool(21, batch=T)
for j in range(T):
    for i in range(3):
        tx = ETx(); tx.add_in(fan.txid(), j); tx.add_out(sv - FEE, ra[i]); tx.add_fee(FEE)
        pre[('bounty', j, i)] = (tx, musig(tx.sighash(0, [(sv, ispk)]), pool2.point(j, outcome_msg(CASE, f'bounty/{j}', f'seat {i}'))))
check('Pre-signed set built with explicit fee outputs', True, f'{len(pre)} payouts + fan-out')

# ---------------------------------------------------------------- 4. settlement
pool.online = set(range(1, 22)) - set(random.sample(range(1, 22), 8))
a_wrong, _ = pool.attest(NON['reward'], outcome_msg(CASE, 'reward', 'paid 60/30/10'))
tx, pr = pre[('reward', 'paid 100/0/0')]; tx.vin[0]['wit'] = [adapt(pr, a_wrong)]
ok, why = etry(tx)
check('A payout completed with another outcome\'s attestation is rejected by the node\'s script check', not ok, why)
for pot, label in (('deposit', 'returned'), ('reward', 'paid 60/30/10')):
    s, _ = pool.attest(NON[pot], outcome_msg(CASE, pot, label))
    tx, pr = pre[(pot, label)]; tx.vin[0]['wit'] = [adapt(pr, s)]
    ok, why = etry(tx)
    check(f'{pot}: "{label}" completed by the threshold attestation and accepted', ok, why)
ok, why = etry(fan); emine(1)
check('Bounty fan-out into slices accepted without the oracle', ok, why)
for j, seat in enumerate([0, 0, 1]):
    s, _ = pool2.attest(j, outcome_msg(CASE, f'bounty/{j}', f'seat {seat}'))
    tx, pr = pre[('bounty', j, seat)]; tx.vin[0]['wit'] = [adapt(pr, s)]
    ok, why = etry(tx)
    check(f'Slice {j} paid to seat {seat} by its own attestation', ok, why)
emine(1)
spent = all(not EL('gettxout', outs[p][0], outs[p][1]) for p in ('deposit', 'reward'))
check('Deposit and reward pots spent on-chain', spent)

# ---------------------------------------------------------------- 5. bond output
Kop, Wop = Key(), Key()
bh = EL('getblockcount') + 30
btree = TapTree(NUMS, [cs(Kop.x, xonly(pool.P)), cs(Wop.x, xonly(pool.P)), cltv(bh, Wop.x)])
B = 200_000 // SCALE
btx, bv = efund(btree.spk(), B)
steal = ETx(); steal.add_in(btx, bv); steal.add_out(B - FEE, dest); steal.add_fee(FEE)
m = steal.sighash(0, [(B, btree.spk())], leaf=btree.scripts[1])
steal.vin[0]['wit'] = [schnorr_sign(m, Wop.d), schnorr_sign(m, Wop.d), btree.scripts[1], btree.control(1)]
check('Bond: the cold wallet key alone cannot withdraw before the fallback', not etry(steal)[0])
forf = ETx(); forf.add_in(btx, bv); forf.add_out(B - FEE, ra[1]); forf.add_fee(FEE)
m = forf.sighash(0, [(B, btree.spk())], leaf=btree.scripts[0])
pre_forf = schnorr_sign(m, Kop.d)                      # pre-signed by the operator when the exposure began
co = pool.frost_sign(m, random.sample(range(1, 22), 11))
forf.vin[0]['wit'] = [co, pre_forf, btree.scripts[0], btree.control(0)]
ok, why = etry(forf); emine(1)
check('Bond: the pre-signed forfeiture completes with the pool\'s co-signature once the outcome is final', ok, why)

# ---------------------------------------------------------------- 6. timelocked fallback
emine(fb_h - EL('getblockcount') + 1)
fb = ETx(locktime=fb_h); fb.add_in(ftxid, fvout, seq=0xfffffffe); fb.add_out(total - FEE, dest); fb.add_fee(FEE)
# the funding output was spent by the incident transaction, so test the fallback on a fresh one
F2 = 50_000 // SCALE
f2tx, f2v = efund(ftree.spk(), F2)
fb = ETx(locktime=EL('getblockcount')); fb.add_in(f2tx, f2v, seq=0xfffffffe); fb.add_out(F2 - FEE, dest); fb.add_fee(FEE)
m = fb.sighash(0, [(F2, ftree.spk())], leaf=ftree.scripts[2])
fb.vin[0]['wit'] = [schnorr_sign(m, W.d), ftree.scripts[2], ftree.control(2)]
ok, why = etry(fb)
check('Funding output: the wallet-alone fallback works after its height', ok, why)
json.dump(results, open('t18_results.json', 'w'), indent=1)
