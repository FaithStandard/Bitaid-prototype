"""Experiment 7 — availability checks for BCAEN base slots (Specification Appendix B.5, §16 item 3).

Rules as drafted: a challenge draws 5 probers from different regions; each sends an ordinary retrieval
within 6 blocks and reports by commit-reveal; if at least 4 of 5 fail, the node gets a 6-block recovery
window, in which a fresh draw of 5 probes again; forfeiture only if that also fails (>= 4 of 5).

Agents:
  honest node   holds the chunk, serves each request with probability `up` (uptime) — each prober's
                path also fails with probability `loss`; with probability `outage` the node's own region
                is down for the whole first round (a local outage).
  deleter       does not hold the chunk: serves nothing.
  partial       holds it but serves a fraction q of requests (rationing bandwidth, or selective).
  watcher       holds it, serves nobody normally, but serves everyone once a challenge is posted
                (challenges are public, so it knows when probes are coming).
Probers: a fraction `liars` of the pool reports failure whatever happens (collusion against a node).
Measured: probability of forfeiture per challenge.
"""
import random, json

def challenge(node, rng, up=0.98, loss=0.02, outage=0.01, liars=0.0, q=0.5, k_fail=4):
    def round_(first):
        region_down = first and rng.random() < outage
        fails = 0
        for p in range(5):
            if rng.random() < liars: fails += 1; continue
            if node == 'deleter': served = False
            elif node == 'honest': served = (rng.random() < up) and (rng.random() > loss) and not (region_down and p == 0)
            elif node == 'partial': served = rng.random() < q and rng.random() > loss
            elif node == 'watcher': served = rng.random() > loss            # challenge is public: it serves
            fails += not served
        return fails >= k_fail
    return round_(True) and round_(False)

out = {}
rng = random.Random(7)
S = 200000
def rate(node, **kw): return round(sum(challenge(node, rng, **kw) for _ in range(S)) / S, 5)
print('Probability of forfeiture per challenge')
for node, kw, label in [
    ('honest', {}, 'honest, 98% uptime, 2% path loss'),
    ('honest', {'up': 0.9, 'loss': 0.1, 'outage': 0.1}, 'honest, poor: 90% uptime, 10% loss, 10% regional outage'),
    ('honest', {'liars': 0.2}, 'honest, 20% of probers lying'),
    ('honest', {'liars': 0.33}, 'honest, a third of probers lying'),
    ('deleter', {}, 'deleted the chunk'),
    ('deleter', {'liars': 0.0, 'loss': 0.0}, 'deleted, perfect network'),
    ('partial', {'q': 0.5}, 'serves half of requests'),
    ('partial', {'q': 0.2}, 'serves a fifth of requests'),
    ('watcher', {}, 'serves only once challenged'),
]:
    out[label] = rate(node, **kw); print(f'  {label:58s} {out[label]}')
json.dump(out, open('e7_results.json', 'w'), indent=1)

# ---- fix: secret spot checks. Each bonded arbitrator learns privately, from a block hash and its own key
# (a VRF), whether it is to probe a given chunk in a period, and proves the assignment only when it
# reports. The node cannot tell a probe from any other retrieval, and no probe is announced.
# A node is forfeited when at least half of its last 20 secret probes failed (provisional).
def spot(node, rng, n_probes=20, thresh=10, up=0.98, loss=0.02, liars=0.0, q=0.5):
    fails = 0
    for _ in range(n_probes):
        if rng.random() < liars: fails += 1; continue
        if node == 'honest': ok = rng.random() < up and rng.random() > loss
        elif node == 'partial': ok = rng.random() < q and rng.random() > loss
        elif node in ('watcher', 'deleter'): ok = False          # nothing announced, so nothing served
        fails += not ok
    return fails >= thresh
print('\nSecret spot checks: probability of forfeiture over 20 probes (forfeit at >= 10 failures)')
out['spot'] = {}
for node, kw, label in [('honest', {}, 'honest, 98% uptime, 2% loss'), ('honest', {'up': 0.9, 'loss': 0.1}, 'honest, poor connection'),
                        ('honest', {'liars': 0.2}, 'honest, 20% of probers lying'), ('honest', {'liars': 0.33}, 'honest, a third lying'),
                        ('partial', {'q': 0.5}, 'serves half'), ('partial', {'q': 0.3}, 'serves 30%'), ('watcher', {}, 'serves only once challenged'), ('deleter', {}, 'deleted')]:
    r = round(sum(spot(node, rng, **kw) for _ in range(S)) / S, 5); out['spot'][label] = r; print(f'  {label:58s} {r}')
json.dump(out, open('e7_results.json', 'w'), indent=1)
