"""Builds VS Code / PowerShell style screenshots of the real console logs -> ../screenshots/"""
import os, sys
sys.path.insert(0, os.path.dirname(__file__))
from term_shot import render
PS = r"PS D:\LABS\MC LAB5>"
SCRIPTS = {"mutual_auth.py": "mp5_1_auth_ids", "signaling_ids.py": "mp5_1_auth_ids", "privacy_checklist.py": "mp5_3_privacy_checklist"}
R = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(R, "screenshots"); os.makedirs(OUT, exist_ok=True)

def lines(p): return open(os.path.join(R, p)).read().rstrip("\n").split("\n")

def between(ls, start, end=None, skip_start=False):
    i = next(k for k, l in enumerate(ls) if start in l)
    j = next((k for k, l in enumerate(ls) if end in l and k > i), len(ls)) if end else len(ls)
    return ls[i + (1 if skip_start else 0):j]

def shot(name, cmd, body, size=14, width=None):
    render("\n".join(["$ " + cmd] + body), os.path.join(OUT, name), ps=PS, scripts=SCRIPTS, size=size, width_chars=width)

A = lines("mp5_1_auth_ids/results/partA_console.txt")
A_CMD = "python mutual_auth.py --runs 2"
shot("5_1_A1_successful_auth.png", A_CMD, between(A, "--- run 1", "--- negative control"), 13, 120)
shot("5_1_A2_forgery_attempts.png", A_CMD, between(A, "--- negative control", "--- Lab task 1"), 13, 140)
shot("5_1_A3_replay.png", A_CMD, between(A, "--- Lab task 1", "--- Lab task 3"), 13, 150)
shot("5_1_A4_mutual_and_simplifications.png", A_CMD, between(A, "--- Lab task 3"), 13, 160)
B = lines("mp5_1_auth_ids/results/partB_console.txt")
shot("5_1_B1_flagged_entries.png", "python signaling_ids.py", between(B, "generated", "-- lab task 2"), 13, 175)
shot("5_1_B2_labtask2_6.png", "python signaling_ids.py", between(B, "-- lab task 2", "-- lab task 5"), 13, 130)
shot("5_1_B3_tuning.png", "python signaling_ids.py", between(B, "-- lab task 5"), 13, 135)
C = lines("mp5_3_privacy_checklist/results/console_log.txt")
shot("5_3_C1_profile_matrix.png", "python privacy_checklist.py", C[:28], 13, 125)
shot("5_3_C2_gap_report.png", "python privacy_checklist.py", between(C, "--- GDPR gap report", "--- LGPD gap report"), 13, 165)
shot("5_3_C3_gap_report_lgpd_dpdp.png", "python privacy_checklist.py", between(C, "--- LGPD gap report", "--- Prioritised"), 13, 170)
shot("5_3_C4_remediation.png", "python privacy_checklist.py", between(C, "--- Prioritised", "notes:"), 12, 190)
print("done")
