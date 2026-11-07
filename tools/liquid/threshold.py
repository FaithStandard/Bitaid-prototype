"""Threshold oracle helpers (Shamir-shared key and nonces, FROST co-signing), from the escrow tests' t5_threshold.py."""
import random
from btc import *

# ------------------------------------------------------------------ Shamir helpers
def share(secret, n, t):
    coeffs = [secret] + [b2i(os.urandom(32)) % n_ for _ in range(t - 1)]
    return {i: sum(c * pow(i, k, n_) for k, c in enumerate(coeffs)) % n_ for i in range(1, n + 1)}
n_ = n   # curve order

def lagrange(i, S):
    num, den = 1, 1
    for j in S:
        if j != i: num = num * j % n_; den = den * (j - i) % n_
    return num * pow(den, n_ - 2, n_) % n_

def interpolate(shares):
    S = list(shares)
    return sum(shares[i] * lagrange(i, S) for i in S) % n_

class Pool:
    def __init__(self, N, batch=6):
        self.N, self.t = N, N // 2 + 1
        x = b2i(os.urandom(32)) % n_
        if not has_even_y(point_mul(G, x)): x = n_ - x          # x-only key, even y
        self.P = point_mul(G, x); self._x = x
        self.x = share(x, N, self.t); self.X = {i: point_mul(G, s) for i, s in self.x.items()}
        self.nonces = []                                       # pre-generated batch
        for _ in range(batch):
            k = b2i(os.urandom(32)) % n_
            if not has_even_y(point_mul(G, k)): k = n_ - k
            ks = share(k, N, self.t)
            self.nonces.append({'R': point_mul(G, k), 'k': ks, 'Rpub': {i: point_mul(G, s) for i, s in ks.items()}, 'used': None})
        self.online = set(range(1, N + 1))

    # ---- attestation with a pre-assigned nonce
    def point(self, j, m):
        R = self.nonces[j]['R']
        e = b2i(tagged('BIP0340/challenge', xonly(R) + xonly(self.P) + m)) % n_
        return point_add(R, point_mul(self.P, e))
    def member_attest(self, i, j, m):
        e = b2i(tagged('BIP0340/challenge', xonly(self.nonces[j]['R']) + xonly(self.P) + m)) % n_
        return (self.nonces[j]['k'][i] + e * self.x[i]) % n_
    def verify_share(self, i, j, m, s_i):
        e = b2i(tagged('BIP0340/challenge', xonly(self.nonces[j]['R']) + xonly(self.P) + m)) % n_
        return point_mul(G, s_i) == point_add(self.nonces[j]['Rpub'][i], point_mul(self.X[i], e))
    def attest(self, j, m, tamper=None):
        """Collect shares from online members in random arrival order; keep the first t that verify."""
        got, rejected = {}, []
        order = list(self.online); random.shuffle(order)
        for i in order:
            s_i = self.member_attest(i, j, m)
            if tamper and i in tamper: s_i = (s_i + 1) % n_
            if self.verify_share(i, j, m, s_i): got[i] = s_i
            else: rejected.append(i)
            if len(got) == self.t: break
        if len(got) < self.t: return None, rejected
        return interpolate(got), rejected

    # ---- FROST co-signature (fresh nonces, two rounds)
    def frost_sign(self, msg, signers):
        S = sorted(signers)
        com = {}
        sec = {}
        for i in S:                                   # round 1: nonce commitments
            d, e = b2i(os.urandom(32)) % n_, b2i(os.urandom(32)) % n_
            sec[i] = (d, e); com[i] = (point_mul(G, d), point_mul(G, e))
        B = b''.join(i.to_bytes(4, 'big') + cbytes(com[i][0]) + cbytes(com[i][1]) for i in S)
        rho = {i: b2i(tagged('FROST/rho', i.to_bytes(4, 'big') + msg + B)) % n_ for i in S}
        R = None
        for i in S: R = point_add(R, point_add(com[i][0], point_mul(com[i][1], rho[i])))
        neg_nonce = not has_even_y(R)
        c = b2i(tagged('BIP0340/challenge', xonly(R) + xonly(self.P) + msg)) % n_
        z = 0
        for i in S:                                   # round 2: signature shares
            d, e = sec[i]
            if neg_nonce: d, e = n_ - d, n_ - e
            z_i = (d + e * rho[i] + lagrange(i, S) * self.x[i] * c) % n_
            # each share is checkable against the member's public commitments and key share
            Ri = point_add(com[i][0], point_mul(com[i][1], rho[i]))
            if neg_nonce: Ri = neg(Ri)
            assert point_mul(G, z_i) == point_add(Ri, point_mul(self.X[i], lagrange(i, S) * c % n_))
            z = (z + z_i) % n_
        return xonly(R) + i2b(z)

