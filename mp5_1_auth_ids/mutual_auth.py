#!/usr/bin/env python3
"""
Mobile Communications - Unit 5 - Mini Project 5.1, Part A
Cellular-style mutual authentication (modelled on GSM A3/A8 and the UMTS/LTE/5G AKA family, Section 5.2)

Everything is in-memory: Device, HomeNetwork, Channel and Attacker are Python objects exchanging plain bytes.
Standard library only (hashlib, hmac, secrets).

    python mutual_auth.py              # full demo (steps 1-9 + lab tasks 1, 3, 4)
    python mutual_auth.py --runs 3     # repeat the successful protocol several times (RAND / session key change each time)
"""
import argparse
import hashlib
import hmac
import secrets
import time

RAND_LEN = 16            # bytes (128-bit challenge, like GSM/AKA RAND)


# ----------------------------------------------------------------------------- primitives
def generate_rand(n=RAND_LEN):
    """Fresh unpredictable challenge, called only by HomeNetwork, once per attempt."""
    return secrets.token_bytes(n)


def compute_response(K, rand):
    """RES = HMAC-SHA256(K, RAND): simplified stand-in for the A3-style function.
    Why this is hard to attack: HMAC-SHA256 is a one-way keyed pseudorandom function (PRF). Seeing
    (RAND, RES) pairs reveals neither K nor RES' for an unseen RAND'; the only generic attack is a search
    over 2**128 (or more) keys."""
    return hmac.new(K, rand, hashlib.sha256).digest()


def derive_session_key(K, rand):
    """Distinct output of the same secret (label-separated), like AKA deriving RES, CK, IK separately."""
    return hmac.new(K, b"SESSIONKEY" + rand, hashlib.sha256).digest()


def compute_network_token(K, rand):
    """Lab task 3: network-to-device proof (AUTN-like), another label-separated HMAC output."""
    return hmac.new(K, b"NETWORKAUTH" + rand, hashlib.sha256).digest()


# ----------------------------------------------------------------------------- entities
class Channel:
    """Everything that crosses the air/core interface is recorded here; an eavesdropper sees all of it."""
    def __init__(self):
        self.sent = []

    def send(self, sender, receiver, label, payload):
        self.sent.append((sender, receiver, label, payload))
        print(f"   [channel] {sender:>11} -> {receiver:<11} {label:<9} {payload.hex()[:32]}...")
        return payload


class Device:
    """Holds K (like Ki on the SIM/USIM). K is never sent."""
    def __init__(self, K):
        self._K = K

    def respond(self, rand):
        return compute_response(self._K, rand)

    def verify_network(self, rand, autn):
        return hmac.compare_digest(autn, compute_network_token(self._K, rand))

    def session_key(self, rand):
        return derive_session_key(self._K, rand)


class HomeNetwork:
    """Holds the same K (like the operator Authentication Center)."""
    def __init__(self, K, track_replay=True):
        self._K = K
        self.track_replay = track_replay
        self.state = {}          # RAND -> "pending" | "used"

    def start_auth(self):
        rand = generate_rand()
        self.state[rand] = "pending"
        return rand, compute_network_token(self._K, rand)

    def verify(self, rand, res):
        """Independently recompute RES and compare in constant time. With track_replay=True, only a RAND that
        was issued by this network and has not been used yet is accepted (freshness, cf. AKA sequence numbers)."""
        if self.track_replay:
            if rand not in self.state:
                return False, "RAND was never issued by this network"
            if self.state[rand] == "used":
                return False, "RAND already used (replay rejected)"
        ok = hmac.compare_digest(res, compute_response(self._K, rand))
        if ok and self.track_replay:
            self.state[rand] = "used"
        return ok, "response matches" if ok else "response mismatch"

    def session_key(self, rand):
        return derive_session_key(self._K, rand)


class Attacker:
    """Sees only what crossed the channel (RAND, RES, AUTN). No reference to K."""
    def __init__(self, observed):
        self.observed = observed          # list of (label, bytes)

    def get(self, label):
        return [p for l, p in self.observed if l == label][-1]


# ----------------------------------------------------------------------------- demo helpers
def hamming(a, b):
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


def run_protocol(K, label="run"):
    ch = Channel()
    device, net = Device(K), HomeNetwork(K)
    print(f"\n--- {label}: mutual authentication ---")
    rand, autn = net.start_auth()
    ch.send("HomeNetwork", "Device", "RAND", rand)
    ch.send("HomeNetwork", "Device", "AUTN", autn)
    net_ok = device.verify_network(rand, autn)
    res = device.respond(rand)
    ch.send("Device", "HomeNetwork", "RES", res)
    ok, why = net.verify(rand, res)
    expected = compute_response(K, rand)
    print(f"   network verifies device : {ok} ({why}); RES == network's own response? "
          f"{hmac.compare_digest(res, expected)}")
    print(f"   device verifies network : {net_ok}")
    ks_dev, ks_net = device.session_key(rand), net.session_key(rand)
    print(f"   session key (device)    : {ks_dev.hex()[:32]}...")
    print(f"   session key (network)   : {ks_net.hex()[:32]}...  identical = {hmac.compare_digest(ks_dev, ks_net)}")
    on_wire = b"".join(p for *_, p in ch.sent)
    print(f"   K appeared on the channel?            {K in on_wire}")
    print(f"   session key appeared on the channel?  {ks_dev in on_wire}")
    print(f"   RES differs from session key (label separation)? {res != ks_dev}")
    return ch, rand, res, ks_dev


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=1)
    args = ap.parse_args()

    print("=" * 96)
    print("Mini Project 5.1 Part A - challenge-response mutual authentication (HMAC-SHA256)")
    print("=" * 96)
    K = secrets.token_bytes(32)                         # step 1: shared secret, stored on both sides, never sent
    print("[step 1] shared secret K generated and stored in Device and HomeNetwork (value not printed)")

    # ---- steps 2-6: successful authentication
    ch, rand1, res1, ks1 = run_protocol(K, "run 1")
    for i in range(2, args.runs + 1):
        _, r, _, ks = run_protocol(K, f"run {i}")
        print(f"   -> RAND differs from run 1: {r != rand1};  session key differs from run 1: {ks != ks1}")

    # ---- negative control: wrong key
    print("\n--- negative control: a device holding a different key ---")
    net = HomeNetwork(K)
    rand, _ = net.start_auth()
    ok, why = net.verify(rand, Device(secrets.token_bytes(32)).respond(rand))
    print(f"   verification result: {ok} ({why})")

    # ---- steps 7-9: attacker
    print("\n--- steps 7-9: attacker who recorded RAND and RES but has no K ---")
    observed = [(l, p) for _, _, l, p in ch.sent]
    atk = Attacker(observed)
    net2 = HomeNetwork(K)
    rand2, autn2 = net2.start_auth()                    # brand-new challenge RAND2
    target = compute_response(K, rand2)
    print(f"   new challenge RAND2 = {rand2.hex()[:32]}...")
    ok, why = net2.verify(rand2, atk.get("RES"))
    print(f"   (a) replay old RES for RAND2           : accepted={ok} ({why})")
    guesses = {"K = RAND": atk.get("RAND"), "K = RES": atk.get("RES"), "K = 16 zero bytes": bytes(16),
               "K = b'secret'": b"secret", "K = first 16 B of RES": atk.get("RES")[:16]}
    for name, g in guesses.items():
        forged = compute_response(g, rand2)
        print(f"   (b) guess {name:<24}: forged RES matches = {hmac.compare_digest(forged, target)}; "
              f"key reproduces the observed RES1 = {hmac.compare_digest(compute_response(g, atk.get('RAND')), atk.get('RES'))}")
    N = 200_000
    t0 = time.time()
    hit = False
    for _ in range(N):
        g = secrets.token_bytes(32)
        if hmac.compare_digest(compute_response(g, atk.get("RAND")), atk.get("RES")):
            hit = True
            break
    dt = time.time() - t0
    rate = N / dt
    years = 2 ** 256 / rate / (3600 * 24 * 365)
    print(f"   (c) brute force: {N:,} random 256-bit keys tried in {dt:.2f} s ({rate:,.0f} keys/s), key found = {hit}")
    print(f"       exhaustive search of 2^256 keys at this rate would take about {years:.1e} years")
    print(f"   (d) forge the network token AUTN with a guess: device would accept = {Device(K).verify_network(rand2, bytes(32))}")
    r_flip = bytes([rand1[0] ^ 1]) + rand1[1:]
    d = hamming(compute_response(K, rand1), compute_response(K, r_flip))
    print(f"   (e) PRF behaviour: flipping ONE bit of RAND changes {d} of 256 bits of RES (~50 % expected)")
    print("   WHY IT FAILS: HMAC-SHA256 is a one-way keyed PRF; (RAND, RES) pairs do not reveal K or predict RES for a new RAND.")

    # ---- lab task 1: replay
    print("\n--- Lab task 1: replay attack ---")
    stateless = HomeNetwork(K, track_replay=False)
    rA, _ = stateless.start_auth()
    resA = Device(K).respond(rA)
    print(f"   legitimate run accepted by network: {stateless.verify(rA, resA)[0]}")
    print(f"   attacker replays captured (RAND, RES) to a STATELESS network: accepted = {stateless.verify(rA, resA)[0]}  <-- replay works")
    print(f"   attacker answers a NEW RAND with the captured RES        : accepted = {stateless.verify(generate_rand(), resA)[0]}")
    tracked = HomeNetwork(K, track_replay=True)
    rB, _ = tracked.start_auth()
    resB = Device(K).respond(rB)
    print(f"   [used-RAND tracking] legitimate run: {tracked.verify(rB, resB)}")
    print(f"   [used-RAND tracking] replayed (RAND, RES): {tracked.verify(rB, resB)}")
    print(f"   [used-RAND tracking] answer to a RAND never issued: {tracked.verify(generate_rand(), resB)}")
    print("   Parallel with real AKA: the network binds each challenge to a sequence number (SQN) carried in AUTN;")
    print("   the SIM rejects a stale SQN, so a recorded RAND/AUTN cannot be replayed to the device either.")

    # ---- lab task 3: mutual authentication
    print("\n--- Lab task 3: network proves itself to the device (AUTN-like token) ---")
    device, net3 = Device(K), HomeNetwork(K)
    rand3, autn3 = net3.start_auth()
    print(f"   genuine network: device accepts token = {device.verify_network(rand3, autn3)}")
    fake_autn = compute_network_token(secrets.token_bytes(32), rand3)      # rogue base station without K
    print(f"   rogue base station (no K) sends its own token: device accepts = {device.verify_network(rand3, fake_autn)}")
    print("   GSM A3 authenticated only the SIM to the network, so a fake BTS could impersonate the network;")
    print("   UMTS AKA adds AUTN so the device also verifies the network.")

    # ---- lab task 4
    print("\n--- Lab task 4: ways this scheme simplifies real 5G AKA ---")
    for i, t in enumerate([
        "No SUCI: the subscriber identity (SUPI/IMSI) would be sent in clear; 5G conceals it with ECIES public-key encryption of the SUPI.",
        "No standardised MILENAGE/TUAK: a generic HMAC-SHA256 stands in for f1-f5 (RES, CK, IK, AK, MAC).",
        "No sequence number / AUTN structure: replay protection here is a used-RAND list, not SQN + AMF + MAC-A with window checks.",
        "No anonymity key (AK) hiding the SQN and no AUTS resynchronisation procedure after a sync failure.",
        "No key hierarchy: real 5G derives K_AUSF -> K_SEAF -> K_AMF -> K_gNB / NAS keys (and separate user-plane keys); here one session key.",
        "No serving-network binding (SNN) in key derivation and no home-network control of the final confirmation (5G AKA / EAP-AKA')."], 1):
        print(f"   {i}. {t}")


if __name__ == "__main__":
    main()
