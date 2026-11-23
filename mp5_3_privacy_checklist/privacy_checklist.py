#!/usr/bin/env python3
"""
Mobile Communications - Unit 5 - Mini Project 5.3
Privacy-compliance checklist tool for a hypothetical mobile app (standard library only).

Checks declared data practices against four frameworks (Section 5.7):
   GDPR (EU), CCPA/CPRA (California), LGPD (Brazil), DPDP Act (India, Data Fiduciary / Data Principal terms)
Each framework has a small, explicit rule set (3-5 checkable rules). Every (practice x framework) cell is marked
compliant / gap / n/a with a reason, followed by a prioritised remediation plan.

    python privacy_checklist.py                # analyse the built-in sample app (FitPulse)
    python privacy_checklist.py --json app.json   # analyse your own profile (same structure as SAMPLE_APP / PRACTICES)

This is a course exercise built from the unit's summary of the laws, NOT legal advice.
"""
import argparse
import csv
import json
import os
from dataclasses import dataclass, field, asdict

HERE = os.path.dirname(os.path.abspath(__file__))

OPT_IN = {"opt_in_dialog", "explicit_opt_in"}            # affirmative, unbundled consent mechanisms
SENSITIVE_HEALTH_BIO = {"health", "biometric"}
SHARING = {"sharing_ads", "sale"}


@dataclass
class Practice:
    id: str
    category: str            # precise_location | contacts | analytics | ad_id | biometric | health
    purpose: str
    purpose_class: str       # service | analytics | advertising | verification | insurance
    basis: str               # declared basis: consent | contract | legitimate_interest
    consent: str             # opt_in_dialog | explicit_opt_in | opt_out_setting | bundled_terms | implied_notice | none
    retention_months: object  # int, or None = indefinite / undefined
    sharing: str             # none | service_provider | sharing_ads | sale
    disclosed: bool          # listed in the notice at collection / privacy notice


SAMPLE_APP = {
    "name": "FitPulse (fitness tracker + social leaderboard)",
    "markets": {"gdpr": True, "ccpa": True, "lgpd": True, "dpdp": True},
    "minors_allowed": True, "min_age": 13, "age_gate": False, "parental_consent": False,
    "opt_out_link": False, "gpc_honored": False, "limit_sensitive_link": False,
    "dpa_in_place": False, "dpo_contact": True, "rights_portal": True,
    "withdrawal_as_easy": False, "grievance_officer": True,
}

SAMPLE_PRACTICES = [
    Practice("P1", "precise_location", "GPS route tracking for runs", "service", "consent", "opt_in_dialog", 24, "none", True),
    Practice("P2", "precise_location", "Location-based advertising via ad network", "advertising", "consent", "bundled_terms", 36, "sharing_ads", True),
    Practice("P3", "health", "Heart-rate and workout insights", "service", "consent", "explicit_opt_in", 24, "none", True),
    Practice("P4", "health", "Wellness-discount programme with partner insurer", "insurance", "consent", "opt_out_setting", 36, "sale", False),
    Practice("P5", "contacts", "Friend finder (contact upload)", "service", "consent", "opt_in_dialog", 12, "none", True),
    Practice("P6", "analytics", "Product analytics (device and usage identifiers)", "analytics", "legitimate_interest", "implied_notice", 18, "service_provider", True),
    Practice("P7", "ad_id", "Personalised ads (advertising ID)", "advertising", "consent", "opt_out_setting", 24, "sharing_ads", True),
    Practice("P8", "biometric", "Face template for photo-verified leaderboards", "verification", "consent", "opt_in_dialog", None, "none", True),
]

# ---------------------------------------------------------------- remediation catalogue (key -> priority, text)
FIX = {
    "unbundle_consent": ("P1", "Replace bundled-terms, implied and opt-out consent with a separate, un-ticked opt-in toggle per purpose "
                               "(location-for-ads, ad ID, analytics, insurer programme); log timestamp, policy version and purpose; "
                               "refusing must not block the core fitness features."),
    "explicit_sensitive": ("P1", "Add a dedicated 'explicit consent' screen for health and biometric data that names the data, purpose and recipients, "
                                 "is separate from the Terms of Service and can be refused without losing core features."),
    "location_optin": ("P1", "Show an opt-in prompt BEFORE precise location is collected and use a second, separate opt-in for advertising uses; "
                             "default to coarse location for any ad purpose."),
    "stop_health_sale": ("P1", "Stop selling or sharing health data with the insurer. If the programme is kept, make it user-initiated (the user exports "
                               "and sends their own data) with explicit consent, a financial-incentive notice and no data flowing by default."),
    "ccpa_links": ("P1", "Add 'Do Not Sell or Share My Personal Information' and 'Limit the Use of My Sensitive Personal Information' links "
                         "(in the app settings and on the web), and honour the Global Privacy Control browser signal."),
    "age_gate": ("P1", "Add an age gate. Require verifiable parental consent below the applicable age (GDPR Art. 8: 13-16 by member state; "
                       "DPDP Act: under 18; CCPA/CPRA: opt-in to sale below 16), and switch off advertising, tracking and behavioural profiling for minors."),
    "notice_update": ("P2", "Update the notice at collection / privacy notice so every category, purpose, recipient (including the insurer partner) "
                            "and retention period is listed before collection."),
    "dpa": ("P2", "Sign data-processing agreements (GDPR Art. 28 / LGPD operator contracts / DPDP processor contracts) with the analytics vendor and "
                  "ad network, and document the legal basis for any international transfer."),
    "retention": ("P2", "Define and enforce a finite retention period for every category (e.g. delete biometric templates on account deletion or "
                        "when the leaderboard feature is switched off); implement automatic purge jobs and publish the periods."),
    "withdrawal": ("P3", "Make withdrawing consent as easy as giving it (one settings toggle per purpose, effective immediately) and publish a "
                         "grievance channel that answers within the statutory period (DPDP Rules: no later than 90 days)."),
}


@dataclass
class Finding:
    rule: str
    status: str          # compliant | gap | n/a
    reason: str
    fix: str = ""


def consent_valid(p):
    return p.consent in OPT_IN


# ---------------------------------------------------------------- GDPR
def check_gdpr(p, app):
    if not app["markets"]["gdpr"]:
        return [Finding("-", "n/a", "no EU users")]
    f = []
    # G1 lawful basis; consent must be affirmative opt-in and unbundled; advertising/analytics on device identifiers need consent
    needs_consent = p.basis == "consent" or p.purpose_class in ("advertising", "analytics", "insurance")
    if needs_consent:
        f.append(Finding("G1 lawful basis / valid consent", "compliant" if consent_valid(p) else "gap",
                         "affirmative opt-in" if consent_valid(p) else f"consent mechanism '{p.consent}' is not an affirmative, unbundled opt-in",
                         "" if consent_valid(p) else "unbundle_consent"))
    else:
        f.append(Finding("G1 lawful basis / valid consent", "compliant", f"basis '{p.basis}' for a core service purpose"))
    # G2 special-category / sensitive: health & biometric -> explicit consent; location treated as sensitive in Section 5.7 -> opt-in before collection
    if p.category in SENSITIVE_HEALTH_BIO:
        ok = p.consent == "explicit_opt_in"
        f.append(Finding("G2 special-category data (Art. 9)", "compliant" if ok else "gap",
                         "explicit consent" if ok else f"{p.category} data needs explicit consent, found '{p.consent}'", "" if ok else "explicit_sensitive"))
    elif p.category == "precise_location":
        ok = consent_valid(p)
        f.append(Finding("G2 location treated as sensitive", "compliant" if ok else "gap",
                         "opt-in before collection" if ok else "no valid opt-in before precise-location collection", "" if ok else "location_optin"))
    # G3 storage limitation
    ok = p.retention_months is not None
    f.append(Finding("G3 storage limitation", "compliant" if ok else "gap",
                     f"retention {p.retention_months} months" if ok else "retention indefinite / undefined", "" if ok else "retention"))
    # G4 third-party sharing: disclosed + processor/recipient agreement
    if p.sharing != "none":
        ok = p.disclosed and app["dpa_in_place"]
        f.append(Finding("G4 recipients and processor contracts", "compliant" if ok else "gap",
                         "disclosed, DPA in place" if ok else ("not disclosed in the notice" if not p.disclosed else "no data-processing agreement with recipient"),
                         "" if ok else ("notice_update" if not p.disclosed else "dpa")))
    return f


# ---------------------------------------------------------------- CCPA / CPRA
def check_ccpa(p, app):
    if not app["markets"]["ccpa"]:
        return [Finding("-", "n/a", "no California consumers / below thresholds")]
    f = []
    f.append(Finding("C1 notice at collection", "compliant" if p.disclosed else "gap",
                     "category, purpose and retention disclosed" if p.disclosed else "category/recipient not disclosed at or before collection",
                     "" if p.disclosed else "notice_update"))
    if p.sharing in SHARING:
        ok = app["opt_out_link"] and app["gpc_honored"]
        f.append(Finding("C2 opt-out of sale / sharing", "compliant" if ok else "gap",
                         "opt-out link + GPC honoured" if ok else "no 'Do Not Sell or Share' link and/or Global Privacy Control not honoured", "" if ok else "ccpa_links"))
    sensitive = p.category in {"precise_location", "biometric", "health"}
    if sensitive and (p.purpose_class != "service" or p.sharing in SHARING):
        ok = app["limit_sensitive_link"]
        f.append(Finding("C3 sensitive personal information", "compliant" if ok else "gap",
                         "right to limit offered" if ok else "sensitive PI (precise geolocation / health / biometric) used beyond the service or sold/shared "
                         "without a 'Limit the Use of My Sensitive Personal Information' link", "" if ok else "ccpa_links"))
    if app["minors_allowed"] and p.sharing in SHARING:
        ok = app["age_gate"]
        f.append(Finding("C4 minors under 16: opt-in to sale/sharing", "compliant" if ok else "gap",
                         "age known, opt-in obtained" if ok else "13-15 year-olds possible; sale/sharing needs their own opt-in (parent below 13) but no age gate", "" if ok else "age_gate"))
    ok = p.retention_months is not None
    f.append(Finding("C5 retention disclosed and limited", "compliant" if ok else "gap",
                     f"retention {p.retention_months} months" if ok else "no retention period", "" if ok else "retention"))
    return f


# ---------------------------------------------------------------- LGPD
def check_lgpd(p, app):
    if not app["markets"]["lgpd"]:
        return [Finding("-", "n/a", "no data subjects in Brazil")]
    f = []
    needs_consent = p.basis == "consent" or p.purpose_class in ("advertising", "insurance")
    if needs_consent:
        f.append(Finding("L1 legal basis (Art. 7) / valid consent (Art. 8)", "compliant" if consent_valid(p) else "gap",
                         "free, informed, unambiguous consent" if consent_valid(p) else f"'{p.consent}' is not specific, unambiguous consent",
                         "" if consent_valid(p) else "unbundle_consent"))
    else:
        f.append(Finding("L1 legal basis (Art. 7) / valid consent (Art. 8)", "compliant", f"legal basis '{p.basis}' for a legitimate service/analytics purpose"))
    if p.category in SENSITIVE_HEALTH_BIO:
        ok = p.consent == "explicit_opt_in"
        f.append(Finding("L2 sensitive personal data (Art. 11)", "compliant" if ok else "gap",
                         "specific, highlighted consent" if ok else f"{p.category} data needs specific and highlighted consent, found '{p.consent}'", "" if ok else "explicit_sensitive"))
    if p.category == "health" and p.sharing in SHARING:
        f.append(Finding("L3 health data shared for economic advantage (Art. 11 par. 4)", "gap",
                         "sharing health data between controllers for economic advantage is prohibited (narrow exceptions)", "stop_health_sale"))
    ok = p.retention_months is not None
    f.append(Finding("L4 necessity / end of processing (Art. 15-16)", "compliant" if ok else "gap",
                     f"retention {p.retention_months} months" if ok else "no end-of-processing point defined", "" if ok else "retention"))
    f.append(Finding("L5 transparency (Art. 9)", "compliant" if p.disclosed else "gap",
                     "disclosed to the data subject" if p.disclosed else "practice not disclosed to the data subject", "" if p.disclosed else "notice_update"))
    return f


# ---------------------------------------------------------------- DPDP Act (Data Fiduciary / Data Principal)
def check_dpdp(p, app):
    if not app["markets"]["dpdp"]:
        return [Finding("-", "n/a", "no Data Principals in India")]
    f = []
    legit_use = p.basis == "contract" and p.purpose_class == "service"
    if legit_use:
        f.append(Finding("D1 notice + consent or legitimate use", "compliant", "legitimate use: service the Data Principal asked for"))
    else:
        ok = consent_valid(p) and p.disclosed
        f.append(Finding("D1 notice + consent or legitimate use", "compliant" if ok else "gap",
                         "itemised notice and affirmative consent" if ok else
                         ("Data Principal not given an itemised notice" if not p.disclosed else f"'{p.consent}' is not free, specific, unambiguous consent by clear affirmative action"),
                         "" if ok else ("notice_update" if not p.disclosed else "unbundle_consent")))
    if app["minors_allowed"] and app["min_age"] < 18 and p.purpose_class in ("advertising", "analytics"):
        ok = app["age_gate"]
        f.append(Finding("D3 no tracking / targeted ads directed at children", "compliant" if ok else "gap",
                         "children identified and excluded" if ok else "tracking / targeted advertising may reach under-18 Data Principals (no age gate)",
                         "" if ok else "age_gate"))
    ok = p.retention_months is not None
    f.append(Finding("D4 erase when purpose is served or consent withdrawn", "compliant" if ok else "gap",
                     f"retention {p.retention_months} months" if ok else "no erasure point defined", "" if ok else "retention"))
    return f


def app_level(app):
    """Checks that concern the whole app rather than a single data practice. Returns {framework: [Finding]}."""
    out = {"GDPR": [], "CCPA/CPRA": [], "LGPD": [], "DPDP Act": []}
    mk = app["markets"]
    if mk["gdpr"] and app["minors_allowed"]:
        ok = app["age_gate"] and app["parental_consent"]
        out["GDPR"].append(Finding("G5 children's consent (Art. 8)", "compliant" if ok else "gap",
                           "age gate + parental authorisation" if ok else f"minimum age {app['min_age']} but no age gate / parental authorisation for consent-based processing", "" if ok else "age_gate"))
    if mk["ccpa"]:
        ok = app["opt_out_link"] and app["gpc_honored"] and app["limit_sensitive_link"]
        out["CCPA/CPRA"].append(Finding("C6 consumer-rights links", "compliant" if ok else "gap",
                           "opt-out, limit-use links and GPC in place" if ok else "no 'Do Not Sell or Share' / 'Limit the Use of My Sensitive PI' links; GPC not honoured", "" if ok else "ccpa_links"))
    if mk["lgpd"]:
        ok = app["rights_portal"] and app["dpo_contact"]
        out["LGPD"].append(Finding("L6 data-subject rights channel + encarregado (Art. 18, 41)", "compliant" if ok else "gap",
                           "rights portal and DPO contact exist" if ok else "missing rights portal / DPO contact", "" if ok else "notice_update"))
    if mk["dpdp"]:
        if app["minors_allowed"] and app["min_age"] < 18:
            ok = app["parental_consent"]
            out["DPDP Act"].append(Finding("D3 verifiable parental consent for children (under 18)", "compliant" if ok else "gap",
                               "verifiable parental consent" if ok else "Data Fiduciary lacks verifiable parental consent for under-18 Data Principals", "" if ok else "age_gate"))
        ok = app["withdrawal_as_easy"] and app["grievance_officer"]
        out["DPDP Act"].append(Finding("D5 easy withdrawal + grievance redressal", "compliant" if ok else "gap",
                           "withdrawal as easy as giving consent; grievance contact published" if ok else
                           ("withdrawing consent is harder than giving it" if not app["withdrawal_as_easy"] else "no grievance contact"), "" if ok else "withdrawal"))
    return out


FRAMEWORKS = {"GDPR": check_gdpr, "CCPA/CPRA": check_ccpa, "LGPD": check_lgpd, "DPDP Act": check_dpdp}


def cell_status(findings):
    st = [x.status for x in findings if x.status != "n/a"]
    if not st:
        return "n/a"
    return "gap" if "gap" in st else "compliant"


def analyse(app, practices):
    results = {}
    for p in practices:
        for fw, fn in FRAMEWORKS.items():
            results[(p.id, fw)] = fn(p, app)
    for fw, fl in app_level(app).items():
        results[("APP", fw)] = fl or [Finding("-", "n/a", "no app-level rule")]
    return results


def remediation_plan(results, practices):
    plan = {}
    for (pid, fw), fl in results.items():
        for x in fl:
            if x.status == "gap" and x.fix:
                e = plan.setdefault(x.fix, {"practices": set(), "frameworks": set(), "rules": set()})
                e["practices"].add(pid); e["frameworks"].add(fw); e["rules"].add(x.rule.split()[0])
    rows = []
    for k, e in plan.items():
        pr, text = FIX[k]
        rows.append({"priority": pr, "fix": k, "action": text, "practices": sorted(e["practices"]), "frameworks": sorted(e["frameworks"]), "rules": sorted(e["rules"])})
    rows.sort(key=lambda r: (r["priority"], -len(r["frameworks"])))
    return rows


def report(app, practices):
    results = analyse(app, practices)
    print("=" * 112)
    print(f"Privacy-compliance checklist for: {app['name']}")
    print("=" * 112)
    print("Declared data practices")
    print(f"{'id':<4}{'category':<18}{'purpose':<48}{'consent':<17}{'retention':<10}{'sharing':<17}{'in notice'}")
    for p in practices:
        print(f"{p.id:<4}{p.category:<18}{p.purpose[:46]:<48}{p.consent:<17}{str(p.retention_months) + ' mo' if p.retention_months else 'none':<10}{p.sharing:<17}{p.disclosed}")
    print(f"app-level: minors allowed={app['minors_allowed']} (min age {app['min_age']}), age gate={app['age_gate']}, parental consent={app['parental_consent']}, "
          f"opt-out link={app['opt_out_link']}, GPC honoured={app['gpc_honored']}, DPA in place={app['dpa_in_place']}")
    print("\nCompliance matrix (compliant / GAP / n/a)")
    fws = list(FRAMEWORKS)
    print(f"{'practice':<22}" + "".join(f"{fw:<13}" for fw in fws))
    counts = {fw: {"gap": 0, "compliant": 0, "n/a": 0} for fw in fws}
    rows_csv = []
    class _A: id = "APP"; category = "app-wide"
    for p in list(practices) + [_A]:
        line = f"{p.id + ' ' + p.category:<22}"
        for fw in fws:
            s = cell_status(results[(p.id, fw)]); counts[fw][s] += 1
            line += f"{s.upper() if s == 'gap' else s:<13}"
            rows_csv.append({"practice": p.id, "category": p.category, "framework": fw, "status": s,
                             "gaps": " | ".join(f"{x.rule}: {x.reason}" for x in results[(p.id, fw)] if x.status == 'gap')})
        print(line)
    print(f"{'TOTAL gaps':<22}" + "".join(f"{counts[fw]['gap']:<13}" for fw in fws))
    for fw in fws:
        print(f"\n--- {fw} gap report ---")
        n = 0
        for p in list(practices) + [_A]:
            for x in results[(p.id, fw)]:
                if x.status == "gap":
                    n += 1
                    print(f"  [{p.id} {p.category}] {x.rule}: {x.reason}")
        if n == 0:
            print("  no gaps")
    plan = remediation_plan(results, practices)
    print("\n--- Prioritised remediation plan (P1 = sensitive data, third-party sharing, minors) ---")
    for i, r in enumerate(plan, 1):
        print(f"  {i}. [{r['priority']}] {r['action']}")
        print(f"       fixes {', '.join(r['rules'])} for {', '.join(r['practices'])} under {', '.join(r['frameworks'])}")
    os.makedirs(os.path.join(HERE, "results"), exist_ok=True)
    with open(os.path.join(HERE, "results", "gap_matrix.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows_csv[0].keys())); w.writeheader(); w.writerows(rows_csv)
    with open(os.path.join(HERE, "results", "remediation_plan.json"), "w") as f:
        json.dump(plan, f, indent=2)
    print("\nnotes: DPDP Rules 2025 were notified in Nov 2025; the substantive duties (notice, consent, retention) apply from May 2027, so the")
    print("DPDP column is a forward-looking check. Under the DPDP Act there is no separate 'sensitive data' category - risk is handled via consent,")
    print("children's rules and Significant Data Fiduciary duties. GDPR does not list precise location as an Art. 9 category; the unit's rule (opt-in")
    print("before location collection) reflects regulators' high-risk treatment and ePrivacy rules.")
    return results, plan


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", help="JSON file {app: {...}, practices: [{...}]}")
    a = ap.parse_args()
    if a.json:
        d = json.load(open(a.json))
        report(d["app"], [Practice(**x) for x in d["practices"]])
    else:
        report(SAMPLE_APP, SAMPLE_PRACTICES)


if __name__ == "__main__":
    main()
