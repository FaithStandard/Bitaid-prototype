"""Minimal, self-contained Bitcoin primitives for Bitaid escrow tests.

secp256k1, BIP340 Schnorr, BIP341 Taproot (script trees, sighash), transaction
serialisation, MuSig2 (BIP327) with adaptor signatures, and a DLC-style oracle.
Written for clarity, not speed: every consensus check is delegated to a real
bitcoind on regtest.
"""
import hashlib, hmac, os, struct, json, subprocess

# ---------------------------------------------------------------- field / curve
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

def _jac(P):
    return None if P is None else (P[0], P[1], 1)

def _jdouble(P):
    if P is None or P[1] == 0: return None
    X, Y, Z = P
    S = 4 * X * Y * Y % p; M = 3 * X * X % p
    X3 = (M * M - 2 * S) % p
    Y3 = (M * (S - X3) - 8 * Y ** 4) % p
    return (X3, Y3, 2 * Y * Z % p)

def _jadd(P, Q):
    if P is None: return Q
    if Q is None: return P
    X1, Y1, Z1 = P; X2, Y2, Z2 = Q
    Z1Z1 = Z1 * Z1 % p; Z2Z2 = Z2 * Z2 % p
    U1 = X1 * Z2Z2 % p; U2 = X2 * Z1Z1 % p
    S1 = Y1 * Z2 * Z2Z2 % p; S2 = Y2 * Z1 * Z1Z1 % p
    if U1 == U2:
        return _jdouble(P) if S1 == S2 else None
    H = U2 - U1; R = S2 - S1
    H2 = H * H % p; H3 = H * H2 % p; U1H2 = U1 * H2 % p
    X3 = (R * R - H3 - 2 * U1H2) % p
    Y3 = (R * (U1H2 - X3) - S1 * H3) % p
    return (X3, Y3, H * Z1 * Z2 % p)

def _aff(P):
    if P is None: return None
    X, Y, Z = P; zi = pow(Z, p - 2, p)
    return (X * zi * zi % p, Y * zi * zi * zi % p)

def point_add(A, B):
    return _aff(_jadd(_jac(A), _jac(B)))

def point_mul(P, k):
    k %= n
    R = None; Q = _jac(P)
    while k:
        if k & 1: R = _jadd(R, Q)
        Q = _jdouble(Q); k >>= 1
    return _aff(R)

def neg(P):
    return None if P is None else (P[0], (p - P[1]) % p)

def has_even_y(P): return P[1] % 2 == 0
def xonly(P): return P[0].to_bytes(32, 'big')
def cbytes(P): return (b'\x02' if has_even_y(P) else b'\x03') + xonly(P)

def lift_x(x):
    if x >= p: return None
    y2 = (pow(x, 3, p) + 7) % p
    y = pow(y2, (p + 1) // 4, p)
    if y * y % p != y2: return None
    return (x, y if y % 2 == 0 else p - y)

def cpoint(b):
    P = lift_x(int.from_bytes(b[1:], 'big'))
    if P is None: raise ValueError('bad point')
    return P if b[0] == 2 else neg(P)

def i2b(x): return (x % n).to_bytes(32, 'big')
def b2i(b): return int.from_bytes(b, 'big')

def sha256(b): return hashlib.sha256(b).digest()
def tagged(tag, msg):
    t = sha256(tag.encode()); return sha256(t + t + msg)

# ---------------------------------------------------------------- keys / BIP340
class Key:
    def __init__(self, sec=None):
        self.d = (b2i(os.urandom(32)) % (n - 1) + 1) if sec is None else sec
        self.P = point_mul(G, self.d)
    @property
    def x(self): return xonly(self.P)

def schnorr_sign(msg, d, aux=None):
    P = point_mul(G, d)
    d = d if has_even_y(P) else n - d
    aux = aux or os.urandom(32)
    t = (d ^ b2i(tagged('BIP0340/aux', aux))).to_bytes(32, 'big')
    k0 = b2i(tagged('BIP0340/nonce', t + xonly(P) + msg)) % n
    R = point_mul(G, k0)
    k = k0 if has_even_y(R) else n - k0
    e = b2i(tagged('BIP0340/challenge', xonly(R) + xonly(P) + msg)) % n
    return xonly(R) + i2b(k + e * d)

def schnorr_verify(msg, px, sig):
    P = lift_x(b2i(px)); r = b2i(sig[:32]); s = b2i(sig[32:])
    if P is None or r >= p or s >= n: return False
    e = b2i(tagged('BIP0340/challenge', sig[:32] + px + msg)) % n
    R = point_add(point_mul(G, s), neg(point_mul(P, e)))
    return R is not None and has_even_y(R) and R[0] == r

# ---------------------------------------------------------------- script / taproot
OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_CLTV, OP_DROP = 0xac, 0xad, 0xb1, 0x75
NUMS = lift_x(0x50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0)

def ser_compact(l):
    if l < 0xfd: return bytes([l])
    if l <= 0xffff: return b'\xfd' + struct.pack('<H', l)
    return b'\xfe' + struct.pack('<I', l)

def push(b):
    assert len(b) < 76
    return bytes([len(b)]) + b

def push_num(v):
    if v == 0: return b'\x00'
    if 1 <= v <= 16: return bytes([0x50 + v])
    out = bytearray()
    while v: out.append(v & 0xff); v >>= 8
    if out[-1] & 0x80: out.append(0)
    return push(bytes(out))

def leaf_hash(script):
    return tagged('TapLeaf', b'\xc0' + ser_compact(len(script)) + script)

def branch(a, b):
    return tagged('TapBranch', min(a, b) + max(a, b))

class TapTree:
    """Taproot output with an internal key and a list of leaf scripts.

    Leaves are arranged in a balanced binary tree; control blocks are computed
    for each leaf."""
    def __init__(self, internal_P, scripts):
        self.internal = internal_P if has_even_y(internal_P) else neg(internal_P)
        self.scripts = scripts
        self.leaves = [leaf_hash(s) for s in scripts]
        self.paths = {i: [] for i in range(len(scripts))}
        nodes = [(h, [i]) for i, h in enumerate(self.leaves)]
        while len(nodes) > 1:
            nxt = []
            for j in range(0, len(nodes), 2):
                if j + 1 == len(nodes): nxt.append(nodes[j]); continue
                (ha, ia), (hb, ib) = nodes[j], nodes[j + 1]
                for i in ia: self.paths[i].append(hb)
                for i in ib: self.paths[i].append(ha)
                nxt.append((branch(ha, hb), ia + ib))
            nodes = nxt
        self.root = nodes[0][0] if scripts else b''
        t = b2i(tagged('TapTweak', xonly(self.internal) + self.root))
        self.Q = point_add(self.internal, point_mul(G, t))
        self.tweak = t
    def spk(self): return b'\x51\x20' + xonly(self.Q)
    def control(self, i):
        return bytes([0xc0 | (0 if has_even_y(self.Q) else 1)]) + xonly(self.internal) + b''.join(self.paths[i])

def keypath_output(P):
    """BIP86-style key-path-only output: Q = P + H(P)G. Returns (Q, tweak)."""
    P = P if has_even_y(P) else neg(P)
    t = b2i(tagged('TapTweak', xonly(P)))
    return point_add(P, point_mul(G, t)), t

# ---------------------------------------------------------------- transactions
class Tx:
    def __init__(self, version=2, locktime=0):
        self.version = version; self.locktime = locktime
        self.vin = []   # dicts: txid(hex), vout, sequence, witness(list)
        self.vout = []  # (value_sats, spk bytes)
    def add_in(self, txid, vout, seq=0xfffffffd):
        self.vin.append({'txid': txid, 'vout': vout, 'seq': seq, 'wit': []})
    def add_out(self, value, spk): self.vout.append((value, spk))
    def _outs(self):
        return b''.join(struct.pack('<q', v) + ser_compact(len(s)) + s for v, s in self.vout)
    def serialize(self, witness=True):
        b = struct.pack('<i', self.version)
        has_w = witness and any(i['wit'] for i in self.vin)
        if has_w: b += b'\x00\x01'
        b += ser_compact(len(self.vin))
        for i in self.vin:
            b += bytes.fromhex(i['txid'])[::-1] + struct.pack('<I', i['vout']) + b'\x00' + struct.pack('<I', i['seq'])
        b += ser_compact(len(self.vout)) + self._outs()
        if has_w:
            for i in self.vin:
                b += ser_compact(len(i['wit'])) + b''.join(ser_compact(len(w)) + w for w in i['wit'])
        return b + struct.pack('<I', self.locktime)
    def hex(self): return self.serialize().hex()
    def txid(self): return sha256(sha256(self.serialize(False)))[::-1].hex()

    def sighash(self, idx, prevouts, leaf=None):
        """BIP341 SIGHASH_DEFAULT. prevouts: list of (value, spk) for every input."""
        sp = sha256(b''.join(bytes.fromhex(i['txid'])[::-1] + struct.pack('<I', i['vout']) for i in self.vin))
        sa = sha256(b''.join(struct.pack('<q', v) for v, _ in prevouts))
        ss = sha256(b''.join(ser_compact(len(s)) + s for _, s in prevouts))
        sq = sha256(b''.join(struct.pack('<I', i['seq']) for i in self.vin))
        so = sha256(self._outs())
        m = b'\x00' + b'\x00' + struct.pack('<i', self.version) + struct.pack('<I', self.locktime)
        m += sp + sa + ss + sq + so
        m += bytes([2 if leaf is not None else 0]) + struct.pack('<I', idx)
        if leaf is not None:
            m += leaf_hash(leaf) + b'\x00' + b'\xff\xff\xff\xff'
        return tagged('TapSighash', m)

# ---------------------------------------------------------------- MuSig2 (BIP327) + adaptors
def keyagg(pubs):
    """pubs: list of compressed 33-byte keys. Returns ctx dict (Q, gacc, tacc, coeffs)."""
    L = tagged('KeyAgg list', b''.join(pubs))
    second = next((pk for pk in pubs if pk != pubs[0]), None)
    coeffs = {}
    Q = None
    for pk in pubs:
        a = 1 if pk == second else b2i(tagged('KeyAgg coefficient', L + pk)) % n
        coeffs[pk] = a
        Q = point_add(Q, point_mul(cpoint(pk), a))
    return {'Q': Q, 'gacc': 1, 'tacc': 0, 'coeffs': coeffs}

def keyagg_xonly_tweak(ctx, t):
    g = 1 if has_even_y(ctx['Q']) else n - 1
    Q2 = point_add(point_mul(ctx['Q'], g), point_mul(G, t))
    return {'Q': Q2, 'gacc': g * ctx['gacc'] % n, 'tacc': (t + g * ctx['tacc']) % n, 'coeffs': ctx['coeffs']}

def taproot_ctx(pubs):
    """Key aggregation plus the BIP86 taproot tweak used by key-path-only outputs."""
    ctx = keyagg(pubs)
    t = b2i(tagged('TapTweak', xonly(ctx['Q'])))
    return keyagg_xonly_tweak(ctx, t)

def nonce_gen():
    k1, k2 = b2i(os.urandom(32)) % n, b2i(os.urandom(32)) % n
    return (k1, k2), (point_mul(G, k1), point_mul(G, k2))

def nonce_agg(pubnonces):
    R1 = None; R2 = None
    for a, b in pubnonces: R1 = point_add(R1, a); R2 = point_add(R2, b)
    return R1 or G, R2 or G  # infinity handling simplified (negligible probability)

def _session(ctx, aggnonce, msg, T=None):
    R1, R2 = aggnonce
    b = b2i(tagged('MuSig/noncecoef', cbytes(R1) + cbytes(R2) + xonly(ctx['Q']) + msg)) % n
    R = point_add(R1, point_mul(R2, b))
    Radapt = point_add(R, T) if T is not None else R
    e = b2i(tagged('BIP0340/challenge', xonly(Radapt) + xonly(ctx['Q']) + msg)) % n
    return b, R, Radapt, e

def partial_sign(ctx, secnonce, d, pk, aggnonce, msg, T=None):
    b, R, Ra, e = _session(ctx, aggnonce, msg, T)
    k1, k2 = secnonce
    if not has_even_y(Ra): k1, k2 = n - k1, n - k2
    g = 1 if has_even_y(ctx['Q']) else n - 1
    a = ctx['coeffs'][pk]
    dd = g * ctx['gacc'] * d % n
    return (k1 + b * k2 + e * a * dd) % n

def partial_verify(ctx, pubnonce, pk, s, aggnonce, msg, T=None):
    b, R, Ra, e = _session(ctx, aggnonce, msg, T)
    Re = point_add(pubnonce[0], point_mul(pubnonce[1], b))
    if not has_even_y(Ra): Re = neg(Re)
    g = 1 if has_even_y(ctx['Q']) else n - 1
    a = ctx['coeffs'][pk]
    gp = g * ctx['gacc'] % n
    rhs = point_add(Re, point_mul(cpoint(pk), e * a * gp % n))
    return point_mul(G, s) == rhs

def partial_agg(ctx, aggnonce, msg, sigs, T=None):
    """Returns the pre-signature (Radapt_x, s') and the nonce parity flag.
    If T is None, the result is a complete BIP340 signature."""
    b, R, Ra, e = _session(ctx, aggnonce, msg, T)
    g = 1 if has_even_y(ctx['Q']) else n - 1
    s = (sum(sigs) + e * g * ctx['tacc']) % n
    return {'rx': xonly(Ra), 's': s, 'odd': not has_even_y(Ra)}

def adapt(presig, t):
    """Complete an adaptor pre-signature with the secret t (the oracle attestation)."""
    s = (presig['s'] - t) % n if presig['odd'] else (presig['s'] + t) % n
    return presig['rx'] + i2b(s)

# ---------------------------------------------------------------- DLC-style oracle
class Oracle:
    """One-key oracle. For an announced event it commits a nonce R; for outcome m
    the attestation point is S_m = R + H(R, X, m)·X and the attestation is the
    BIP340 s-value, with s·G = S_m. Signing two outcomes under one R leaks the key."""
    def __init__(self):
        self.key = Key()
        if not has_even_y(self.key.P): self.key = Key(n - self.key.d)
        self.events = {}
    def announce(self, event):
        k = Key()
        if not has_even_y(k.P): k = Key(n - k.d)
        self.events[event] = k
        return k.P
    def point(self, R, m):
        e = b2i(tagged('BIP0340/challenge', xonly(R) + self.key.x + m)) % n
        return point_add(R, point_mul(self.key.P, e))
    def attest(self, event, m):
        k = self.events[event]
        e = b2i(tagged('BIP0340/challenge', k.x + self.key.x + m)) % n
        return (k.d + e * self.key.d) % n

def outcome_msg(case, pot, label):
    return tagged('Bitaid/outcome', case.encode() + b'|' + pot.encode() + b'|' + label.encode())

# ---------------------------------------------------------------- RPC
class Node:
    def __init__(self, cli):
        self.cli = cli
    def __call__(self, *args, wallet=None):
        cmd = list(self.cli) + ([f'-rpcwallet={wallet}'] if wallet else []) + [str(a) if not isinstance(a, (dict, list)) else json.dumps(a) for a in args]
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode:
            raise RPCError(r.stderr.strip())
        out = r.stdout.strip()
        try: return json.loads(out)
        except Exception: return out

class RPCError(Exception):
    pass

BTC = Node(['/home/claude/nodes/bitcoin-31.1/bin/bitcoin-cli', '-regtest', '-rpcuser=u', '-rpcpassword=p', '-rpcport=18443'])

_MINE_DESC = None
def mine(k=1):
    """Mine k blocks to a key outside the wallet (much faster than wallet addresses)."""
    global _MINE_DESC
    if _MINE_DESC is None:
        d = 'raw(5120' + xonly(Key().P).hex() + ')'
        _MINE_DESC = BTC('getdescriptorinfo', d)['descriptor']
    if _MOCK is None: _sync_clock()
    return BTC('generatetodescriptor', k, _MINE_DESC)

_MOCK = None
def _sync_clock():
    """After a restart the node's clock is real time, but earlier tests advanced the chain into
    the future; keep the mock clock ahead of the chain so new blocks are valid."""
    global _MOCK
    import time as _t
    mtp = BTC('getblockchaininfo')['mediantime']
    _MOCK = max(int(_t.time()), mtp + 3600)
    BTC('setmocktime', _MOCK)
def mine_to(height):
    """Mine up to a height, advancing the node's clock ten minutes per block so that
    long timelocks (90 or 365 days) can be reached on regtest."""
    global _MOCK
    import time as _t
    if _MOCK is None: _sync_clock()
    left = height - BTC('getblockcount')
    while left > 0:
        k = min(left, 1000)
        _MOCK += 600 * k
        BTC('setmocktime', _MOCK)
        mine(k); left -= k

def fund(spk, sats):
    """Send sats to a raw scriptPubKey from the regtest wallet; returns (txid, vout)."""
    t = Tx(); t.add_out(sats, spk)
    funded = BTC('fundrawtransaction', t.serialize(False).hex(), {'fee_rate': 2}, wallet='w')
    signed = BTC('signrawtransactionwithwallet', funded['hex'], wallet='w')
    txid = BTC('sendrawtransaction', signed['hex'])
    dec = BTC('decoderawtransaction', signed['hex'])
    vout = next(o['n'] for o in dec['vout'] if o['scriptPubKey']['hex'] == spk.hex())
    mine(1)
    return txid, vout

def try_broadcast(tx):
    """Returns (accepted, reason)."""
    res = BTC('testmempoolaccept', [tx.hex()])[0]
    if not res['allowed']:
        return False, res.get('reject-reason', '?') + (' ' + res.get('reject-details', '') if res.get('reject-details') else '')
    BTC('sendrawtransaction', tx.hex())
    return True, 'accepted'

def addr_spk(addr):
    return bytes.fromhex(BTC('getaddressinfo', addr, wallet='w')['scriptPubKey'])
