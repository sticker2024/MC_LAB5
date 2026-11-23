#!/usr/bin/env python3
"""
Mobile Communications - Unit 5 - Mini Project 5.1, Part B
Rule-based, telecom-aware intrusion detection over a SYNTHETIC signaling log (Section 5.3 concept).

Rules implemented
  R1 schema / conformance : missing field, event_type outside the allowed set, non-numeric timestamp
  R2 implausible travel   : per subscriber, consecutive events (sorted by time) with a country change inside the
                            minimum plausible travel time  d / V_MAX   (adjacent countries use a border-region distance)
  R3 auth_request rate    : more than RATE_N auth_request events from one subscriber in RATE_WINDOW seconds   (lab task 2)
  R4 monotonic timestamps : per subscriber, ARRIVAL order must have non-decreasing timestamps                  (lab task 6)

    python signaling_ids.py              # demo log + flagged entries + large-log threshold tuning
    python signaling_ids.py --seed 7
"""
import argparse
import math
import random
from datetime import datetime, timedelta, timezone

BASE = datetime(2026, 11, 23, 0, 0, tzinfo=timezone.utc)
ALLOWED = {"attach", "detach", "location_update", "auth_request"}
REQUIRED = ("timestamp", "subscriber_id", "event_type", "country")
CAPITALS = {"RW": (-1.9441, 30.0619), "UG": (0.3476, 32.5825), "KE": (-1.2921, 36.8219), "TZ": (-6.7924, 39.2083),
            "CD": (-4.4419, 15.2663), "FR": (48.8566, 2.3522), "AE": (24.4539, 54.3773), "US": (38.9072, -77.0369),
            "CN": (39.9042, 116.4074)}
ADJACENT = {frozenset(p) for p in [("RW", "UG"), ("RW", "TZ"), ("RW", "CD"), ("UG", "KE"), ("UG", "TZ"), ("UG", "CD"), ("KE", "TZ")]}
BORDER_KM = 60.0            # assumed effective distance between adjacent countries (border towns), not capital-to-capital
V_MAX_DEFAULT = 900.0       # km/h (airliner cruise)
RATE_N, RATE_WINDOW = 5, 60  # more than 5 auth_requests in 60 s


def haversine(a, b):
    la1, lo1, la2, lo2 = map(math.radians, (*a, *b))
    h = math.sin((la2 - la1) / 2) ** 2 + math.cos(la1) * math.cos(la2) * math.sin((lo2 - lo1) / 2) ** 2
    return 2 * 6371.0 * math.asin(math.sqrt(h))


def distance_km(c1, c2, use_adjacency=True):
    if use_adjacency and frozenset((c1, c2)) in ADJACENT:
        return BORDER_KM
    return haversine(CAPITALS[c1], CAPITALS[c2])


def min_travel_s(c1, c2, vmax=V_MAX_DEFAULT, use_adjacency=True):
    return distance_km(c1, c2, use_adjacency) / vmax * 3600.0


def iso(ts):
    return (BASE + timedelta(seconds=ts)).strftime("%m-%d %H:%M:%S") if isinstance(ts, (int, float)) else str(ts)


# --------------------------------------------------------------------------- synthetic log
def generate_signaling_log(n, seed=1, n_sub=None, anomalies=None):
    """Returns (events, truth). events = list of dicts in ARRIVAL order (no labels).
    truth = parallel list: None for legitimate events, else (anomaly_id, kind). Only the evaluator uses truth."""
    rng = random.Random(seed)
    n_sub = n_sub or max(10, n // 60)
    anomalies = anomalies or {"travel": 1, "malformed_missing": 1, "malformed_type": 1, "burst": 1, "out_of_order": 1}
    items = []     # (timestamp, event, truth)

    def ev(t, sub, typ, ctry):
        return {"timestamp": t, "subscriber_id": sub, "event_type": typ, "country": ctry}

    def rtype():
        return rng.choices(["location_update", "attach", "auth_request", "detach"], [6, 2, 3, 1])[0]

    per_sub = max(2, n // n_sub)
    for i in range(n_sub):
        sub = f"SUB{i:04d}"
        home = rng.choices(["RW", "UG", "KE", "TZ"], [8, 1, 1, 1])[0]
        kind = rng.random()
        times = sorted(rng.uniform(0, 86000) for _ in range(per_sub))
        if kind < 0.06:                       # legitimate air traveller
            dest = rng.choice([c for c in ("FR", "AE", "KE", "US", "CN") if c != home])
            dep = rng.uniform(10000, 40000)
            flight = distance_km(home, dest, True) / 800.0 * 3600 + rng.uniform(3600, 9000)   # flight + airport overhead
            for t in times:
                items.append((t if t < dep else t + flight, ev(t if t < dep else t + flight, sub, rtype(), home if t < dep else dest), None))
        elif kind < 0.14:                     # legitimate border-town hopper (home <-> adjacent country, minutes apart)
            nb = rng.choice([c for c in ("UG", "CD", "TZ") if frozenset((home, c)) in ADJACENT] or ["UG"])
            t = rng.uniform(0, 20000)
            cur = home
            for _ in range(per_sub):
                items.append((t, ev(t, sub, rtype(), cur), None))
                t += rng.uniform(300, 3000)
                cur = nb if cur == home else home
        else:
            for t in times:
                items.append((t, ev(t, sub, rtype(), home), None))

    aid = 0
    # --- injected anomalies on dedicated subscribers
    for _ in range(anomalies.get("travel", 0)):
        aid += 1; sub = f"ANOM{aid:03d}"
        home = "RW"; far = rng.choice(["FR", "AE", "US", "CN", "KE"])
        t0 = rng.uniform(20000, 70000)
        f = rng.uniform(0.02, 1.3)             # gap as a fraction of the 900 km/h minimum travel time (>=1: 'plausible-looking')
        gap = max(30.0, f * min_travel_s(home, far, 900.0))
        for k in range(3):
            items.append((t0 - 600 * (3 - k), ev(t0 - 600 * (3 - k), sub, rtype(), home), None))
        items.append((t0, ev(t0, sub, "location_update", home), None))
        items.append((t0 + gap, ev(t0 + gap, sub, "location_update", far), (aid, "travel")))
    for _ in range(anomalies.get("malformed_missing", 0)):
        aid += 1; sub = f"ANOM{aid:03d}"; t0 = rng.uniform(0, 80000)
        e = ev(t0, sub, rtype(), "RW"); del e[rng.choice(["country", "subscriber_id", "event_type"])]
        items.append((t0, e, (aid, "malformed_missing")))
    for _ in range(anomalies.get("malformed_type", 0)):
        aid += 1; sub = f"ANOM{aid:03d}"; t0 = rng.uniform(0, 80000)
        items.append((t0, ev(t0, sub, rng.choice(["ss7_update_loc_ex", "attach_all", "LOCATIONUPDATE"]), "RW"), (aid, "malformed_type")))
    for _ in range(anomalies.get("burst", 0)):
        aid += 1; sub = f"ANOM{aid:03d}"; t0 = rng.uniform(0, 80000)
        for k in range(12):
            tt = t0 + k * 2.0
            items.append((tt, ev(tt, sub, "auth_request", "RW"), (aid, "burst")))
    out_of_order_after = []
    for _ in range(anomalies.get("out_of_order", 0)):
        aid += 1; sub = f"ANOM{aid:03d}"; t0 = rng.uniform(20000, 70000)
        items.append((t0, ev(t0, sub, "location_update", "RW"), None))
        items.append((t0 + 1, ev(t0 + 1, sub, "auth_request", "RW"), None))
        # arrives AFTER the t0+1 event but carries an earlier timestamp (clock skew / replay / tampering)
        items.append((t0 + 2, ev(t0 - 3 * 3600, sub, "location_update", "RW"), (aid, "out_of_order")))

    items.sort(key=lambda x: x[0])           # arrival order follows the *arrival* key (index 0), not the event timestamp
    events = [dict(e) for _, e, _ in items]
    truth = [t for _, _, t in items]
    return events, truth


# --------------------------------------------------------------------------- detector
def detect(events, vmax=V_MAX_DEFAULT, use_adjacency=True, rules=("R1", "R2", "R3", "R4")):
    """Returns a list of (event_index, rule, detail). Uses ONLY the event dicts (never the ground truth)."""
    flags = []
    valid = []
    if "R1" in rules:
        for i, e in enumerate(events):
            missing = [f for f in REQUIRED if f not in e]
            if missing:
                flags.append((i, "R1", f"missing field(s): {', '.join(missing)}")); continue
            if e["event_type"] not in ALLOWED:
                flags.append((i, "R1", f"invalid event_type '{e['event_type']}'")); continue
            if not isinstance(e["timestamp"], (int, float)):
                flags.append((i, "R1", "non-numeric timestamp")); continue
            if e["country"] not in CAPITALS:
                flags.append((i, "R1", f"unknown country '{e['country']}'")); continue
            valid.append(i)
    else:
        valid = [i for i, e in enumerate(events) if all(f in e for f in REQUIRED) and e["event_type"] in ALLOWED]
    by_sub = {}
    for i in valid:
        by_sub.setdefault(events[i]["subscriber_id"], []).append(i)
    for sub, idxs in by_sub.items():
        if "R2" in rules:
            s = sorted(idxs, key=lambda i: events[i]["timestamp"])
            for a, b in zip(s[:-1], s[1:]):
                ea, eb = events[a], events[b]
                if ea["country"] != eb["country"]:
                    gap = eb["timestamp"] - ea["timestamp"]
                    need = min_travel_s(ea["country"], eb["country"], vmax, use_adjacency)
                    if gap < need:
                        flags.append((b, "R2", f"{ea['country']}->{eb['country']} in {gap/60:.0f} min, plausible minimum {need/60:.0f} min "
                                               f"({distance_km(ea['country'], eb['country'], use_adjacency):.0f} km at {vmax:.0f} km/h)"))
        if "R3" in rules:
            auth = [i for i in idxs if events[i]["event_type"] == "auth_request"]
            auth.sort(key=lambda i: events[i]["timestamp"])
            lo = 0
            for hi in range(len(auth)):
                while events[auth[hi]]["timestamp"] - events[auth[lo]]["timestamp"] > RATE_WINDOW:
                    lo += 1
                if hi - lo + 1 > RATE_N:
                    flags.append((auth[hi], "R3", f"{hi - lo + 1} auth_requests within {RATE_WINDOW} s (limit {RATE_N})"))
        if "R4" in rules:
            prev = None
            for i in idxs:                   # arrival order
                t = events[i]["timestamp"]
                if prev is not None and t < prev:
                    flags.append((i, "R4", f"timestamp {iso(t)} earlier than previous {iso(prev)} (non-monotonic arrival)"))
                prev = max(prev, t) if prev is not None else t
    flags.sort(key=lambda f: (f[0], f[1]))
    return flags


# --------------------------------------------------------------------------- evaluation
def evaluate(events, truth, flags, kinds=None, rules=None):
    """Per-anomaly recall and per-event precision, optionally restricted to given anomaly kinds / rules."""
    fl = [f for f in flags if (rules is None or f[1] in rules)]
    flagged_idx = {f[0] for f in fl}
    anomalies = {}
    for i, t in enumerate(truth):
        if t and (kinds is None or t[1] in kinds):
            anomalies.setdefault(t[0], []).append(i)
    tp_a = sum(1 for idxs in anomalies.values() if any(i in flagged_idx for i in idxs))
    fn = len(anomalies) - tp_a
    bad_idx = {i for i, t in enumerate(truth) if t and (kinds is None or t[1] in kinds)}
    fp = len([i for i in flagged_idx if truth[i] is None])
    return {"anomalies": len(anomalies), "detected": tp_a, "missed": fn, "false_pos_events": fp, "flagged_events": len(flagged_idx)}


def show_flags(events, truth, flags, limit=None):
    print(f"{'idx':>4}  {'time':<16}{'subscriber':<10} {'event_type':<18}{'country':<8}{'rule':<5}detail  [ground truth]")
    for i, rule, detail in flags[:limit]:
        e = events[i]
        t = truth[i]
        gt = f"INJECTED:{t[1]}" if t else "legitimate (false positive)"
        print(f"{i:>4}  {iso(e.get('timestamp', '?')):<16}{str(e.get('subscriber_id', '-')):<10} {str(e.get('event_type', '-')):<18}"
              f"{str(e.get('country', '-')):<8}{rule:<5}{detail}  [{gt}]")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=3)
    a = ap.parse_args()

    print("=" * 110)
    print("Mini Project 5.1 Part B - signaling-plane IDS on a synthetic log")
    print("=" * 110)
    events, truth = generate_signaling_log(70, seed=a.seed)
    inj = sorted({t[1] for t in truth if t})
    print(f"generated {len(events)} events (seed {a.seed}); injected anomaly kinds: {', '.join(inj)}")
    print("sample of ordinary events:")
    for e in [x for x, t in zip(events, truth) if t is None][:4]:
        print("   ", {k: (iso(v) if k == 'timestamp' else v) for k, v in e.items()})

    print("\n-- detector run: all four rules (R1 schema, R2 travel @900 km/h, R3 auth rate, R4 monotonic) --")
    flags = detect(events)
    show_flags(events, truth, flags, limit=30)
    ev_ = evaluate(events, truth, flags)
    print(f"\nsummary: {ev_['anomalies']} injected anomalies, {ev_['detected']} detected, {ev_['missed']} missed; "
          f"{ev_['flagged_events']} events flagged ({ev_['false_pos_events']} legitimate events flagged).")
    flagged_idx = {f[0] for f in flags}
    for i, t in enumerate(truth):
        if t and t[1] == "travel" and i not in flagged_idx:
            e = events[i]
            prev = max((j for j in range(len(events)) if events[j].get("subscriber_id") == e["subscriber_id"] and events[j]["timestamp"] < e["timestamp"]), key=lambda j: events[j]["timestamp"])
            gap = e["timestamp"] - events[prev]["timestamp"]
            need = min_travel_s(events[prev]["country"], e["country"])
            print(f"missed (false negative): {e['subscriber_id']} {events[prev]['country']}->{e['country']} in {gap/3600:.1f} h; "
                  f"900 km/h minimum is {need/3600:.1f} h, so the move looks physically possible (a lenient threshold hides spoofing just inside the limit)")
    print(f"ordinary events passed unflagged: {sum(1 for t in truth if t is None) - ev_['false_pos_events']} of {sum(1 for t in truth if t is None)}")

    print("\n-- lab task 2: auth_request rate rule (R3) tested against the burst anomaly --")
    r3 = [f for f in detect(events, rules=('R1', 'R3'), ) if f[1] == 'R3']
    print(f"   R3 flagged {len(r3)} events; first at idx {r3[0][0] if r3 else '-'}: {r3[0][2] if r3 else ''}")
    print(f"   without R3 the burst is detected: {evaluate(events, truth, detect(events, rules=('R1','R2','R4')), kinds={'burst'})['detected']} of 1")

    print("\n-- lab task 6: non-monotonic timestamp rule (R4) --")
    r4 = [f for f in flags if f[1] == "R4"]
    for i, rule, d in r4:
        print(f"   idx {i}: {d}")
    print("   Real meaning: a signalling message with an older timestamp arriving later = clock skew between nodes,")
    print("   buffered/delayed delivery, a replayed or injected message, or log tampering - worth investigating.")

    # ---- lab task 5: tuning on a larger log
    big_n = 20000
    anomalies = {"travel": 80, "malformed_missing": 20, "malformed_type": 20, "burst": 15, "out_of_order": 15}
    big, btruth = generate_signaling_log(big_n, seed=11, n_sub=320, anomalies=anomalies)
    print(f"\n-- lab task 5: larger log: {len(big)} events, {sum(1 for t in btruth if t is None)} legitimate, injected {anomalies} --")
    print("   (legitimate traffic includes ~6 % air travellers and ~8 % border-town hoppers; 80 travel anomalies have gaps")
    print("    from 2 % to 130 % of the 900 km/h minimum travel time, so the hardest ones look 'plausible')")
    print(f"\n   {'V_MAX (km/h)':>12} {'adjacency':>10} | {'travel anomalies':>16} {'detected':>9} {'missed (FN)':>12} | {'legit events flagged (FP)':>26} {'precision':>10} {'recall':>8}")
    tuning = []
    for vmax in (100, 200, 400, 900, 1500, 3000):
        for adj in (True, False):
            fl = [f for f in detect(big, vmax=vmax, use_adjacency=adj, rules=("R1", "R2")) if f[1] == "R2"]
            r = evaluate(big, btruth, fl, kinds={"travel"})
            fp = r["false_pos_events"]
            tp_ev = len({f[0] for f in fl if btruth[f[0]] and btruth[f[0]][1] == "travel"})
            prec = tp_ev / max(1, len({f[0] for f in fl}))
            rec = r["detected"] / r["anomalies"]
            print(f"   {vmax:>12} {('on' if adj else 'off'):>10} | {r['anomalies']:>16} {r['detected']:>9} {r['missed']:>12} | {fp:>26} {prec:>10.3f} {rec:>8.3f}")
            tuning.append((vmax, adj, r["anomalies"], r["detected"], r["missed"], fp, prec, rec))
    import csv, os
    os.makedirs(os.path.join(os.path.dirname(os.path.abspath(__file__)), "results"), exist_ok=True)
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "results", "labtask5_threshold_tuning.csv"), "w", newline="") as f:
        w = csv.writer(f); w.writerow(["vmax_kmh", "adjacency_exemption", "travel_anomalies", "detected", "missed_FN", "legit_flagged_FP", "precision", "recall"]); w.writerows(tuning)
    full = evaluate(big, btruth, detect(big), None)
    print(f"\n   all four rules at 900 km/h, adjacency on: {full['detected']}/{full['anomalies']} injected anomalies detected, "
          f"{full['false_pos_events']} legitimate events flagged of {sum(1 for t in btruth if t is None)}.")
    print("   Reading: a low V_MAX (strict) flags genuine air travellers -> false positives; a high V_MAX (lenient) lets spoofed")
    print("   locations whose gap exceeds d/V_MAX slip through -> false negatives; without the border exemption legitimate")
    print("   border-town hopping is flagged whatever V_MAX is chosen.")


if __name__ == "__main__":
    main()
