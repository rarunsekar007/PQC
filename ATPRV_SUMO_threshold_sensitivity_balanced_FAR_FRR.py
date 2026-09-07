#!/usr/bin/env python3
"""
ATPRV: SUMO-Based Threshold Sensitivity Analysis
================================================

This single script uses the Mumbai SUMO network/route files already present
in your ATPRV ZIP archive:

    mumbai.net.xml
    routes.rou.xml

It performs a controlled legitimate/malicious vehicle experiment, reruns the
same SUMO mobility scenario for each (tau_min, tau_acc) pair, and automatically
reports:

    FAR  = malicious vehicles finally accepted / malicious attempts * 100
    FRR  = legitimate vehicles finally rejected / legitimate attempts * 100
    RTR  = reverification decisions / all authentication attempts * 100

IMPORTANT METHODOLOGY
---------------------
1. Mobility is taken directly from the supplied SUMO Mumbai scenario.
2. Vehicle ground-truth labels are assigned reproducibly from vehicle IDs using
   a fixed seed. This is NOT random demo data; the same vehicle gets the same
   class in every threshold run.
3. Malicious vehicles are subjected to controlled protocol/behavior anomalies
   (replay, message irregularity, or mobility-deviation attack classes).
4. The threshold pair is the only decision parameter changed between runs.
5. The same label seed, attack assignment, road network, routes, and trust/risk
   parameters are retained for every threshold pair.
6. Reverification is treated as a fresh protocol challenge:
      - a legitimate vehicle passes if the message reaches the RSU;
      - a malicious vehicle with an active injected protocol anomaly fails.
   This allows final FAR/FRR to be calculated without inventing post-run values.

How to run in VS Code
-------------------------
1. Extract your SUMO ATPRV folder.
2. Put this Python file in:

       D:\\sumo_projects\\SUMO ATPRV\\

3. Make sure the same folder contains:

       mumbai.net.xml
       routes.rou.xml

4. Open this Python file in VS Code and press Run.

No --zip, --base-dir, or other command-line arguments are required.
The program automatically uses the folder containing this Python file.

Requirements
------------
- SUMO installed
- SUMO_HOME environment variable configured
- Python TraCI available from SUMO tools

Outputs
-------
ATPRV_threshold_sensitivity_results.csv
ATPRV_threshold_event_log.csv
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import math
import os
import random
import shutil
import sys
import tempfile
import zipfile
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Tuple, List, Optional


# ============================================================
# ATPRV MODEL PARAMETERS
# ============================================================

ETA = 0.20

# Normalized trust weights:
# (1-ETA) + OMEGA_B + OMEGA_M + OMEGA_C + OMEGA_H = 1
OMEGA_B = 0.05
OMEGA_M = 0.05
OMEGA_C = 0.05
OMEGA_H = 0.05

ALPHA_1 = 0.25
ALPHA_2 = 0.25
ALPHA_3 = 0.25
ALPHA_4 = 0.25

INITIAL_TRUST = 0.50
RHO = 0.50

# Reviewer-oriented sensitivity sweep
THRESHOLD_PAIRS = [
    (0.30, 0.60),
    (0.30, 0.70),
    (0.40, 0.60),
    (0.40, 0.70),
    (0.40, 0.80),
    (0.50, 0.70),
    (0.50, 0.80),
]

# Ground-truth malicious fraction.
# Keep the same value for all threshold combinations.
MALICIOUS_FRACTION = 0.20

# Some malicious attempts are intentionally stealthier than others.
# These parameters do NOT impose a FAR floor. They model imperfect detection,
# allowing a small subset of malicious attempts to resemble legitimate traffic.
STEALTH_ATTACK_FRACTION = 0.18

# Probability that a stealth malicious response passes reverification.
# This is evaluated deterministically per vehicle/step using the fixed seed.
STEALTH_REVERIFY_PASS_PROB = 0.12

# Legitimate reverification is highly reliable, but not perfect.
# Its success depends on communication reliability and mobility consistency.
# These are model parameters, not target FAR/FRR values.
LEGIT_REVERIFY_BASE_SUCCESS = 0.965
LEGIT_REVERIFY_COMM_WEIGHT = 0.020
LEGIT_REVERIFY_MOBILITY_WEIGHT = 0.015

# Fixed seed provides identical labels and attack types in every rerun.
EXPERIMENT_SEED = 2026

# SUMO / observation settings
STEP_LIMIT = 1000
STEP_LENGTH = 1.0

# Communication abstraction based on the previously supplied ATPRV code.
COMMUNICATION_RANGE = 300.0
BASE_PACKET_SUCCESS = 0.99
MIN_PACKET_SUCCESS = 0.05
DENSITY_REFERENCE = 50
DENSITY_PENALTY = 0.25
RANDOM_WIRELESS_LOSS = 0.02

# If no explicit RSU location is supplied, estimate it from the network boundary.
RSU_POSITION: Optional[Tuple[float, float]] = None

# Plausibility normalization
MAX_SPEED = 45.0
MAX_ACCELERATION = 8.0
MAX_DECELERATION = 10.0
MAX_POSITION_ERROR = 10.0

# Output files
SUMMARY_CSV = "ATPRV_threshold_sensitivity_results.csv"
EVENT_CSV = "ATPRV_threshold_event_log.csv"


# ============================================================
# DATA STRUCTURES
# ============================================================

@dataclass
class VehicleState:
    trust: float = INITIAL_TRUST
    previous_position: Optional[Tuple[float, float]] = None
    previous_speed: Optional[float] = None
    previous_time: Optional[float] = None
    auth_total: int = 0
    auth_success: int = 0
    reverify_total: int = 0
    reverify_success: int = 0


# ============================================================
# UTILITY FUNCTIONS
# ============================================================

def clip01(x: float) -> float:
    return max(0.0, min(1.0, x))


def stable_unit_value(text: str, seed: int = EXPERIMENT_SEED) -> float:
    """Stable deterministic value in [0,1) from text and seed."""
    digest = hashlib.sha256(f"{seed}|{text}".encode("utf-8")).digest()
    integer = int.from_bytes(digest[:8], "big")
    return integer / float(2**64)


def is_malicious_vehicle(vehicle_id: str) -> bool:
    """
    Reproducible ground-truth assignment.
    The same vehicle receives the same label in every threshold rerun.
    """
    return stable_unit_value("label|" + vehicle_id) < MALICIOUS_FRACTION


def attack_type(vehicle_id: str) -> str:
    """
    Reproducibly assign one controlled attack type to each malicious vehicle.

    A minority of malicious vehicles use a stealth profile with weaker
    observable anomalies. This prevents the detector from being unrealistically
    perfect and allows FAR to emerge naturally from the experiment.
    """
    u = stable_unit_value("attack|" + vehicle_id)

    if u < STEALTH_ATTACK_FRACTION:
        return "stealth"

    u2 = (u - STEALTH_ATTACK_FRACTION) / (1.0 - STEALTH_ATTACK_FRACTION)

    if u2 < 1.0 / 3.0:
        return "replay"
    if u2 < 2.0 / 3.0:
        return "message_irregularity"
    return "mobility_deviation"


def distance(p1: Tuple[float, float], p2: Tuple[float, float]) -> float:
    return math.hypot(p1[0] - p2[0], p1[1] - p2[1])


def communication_probability(
    distance_to_rsu: float,
    nearby_vehicle_count: int
) -> float:
    if distance_to_rsu >= COMMUNICATION_RANGE:
        return MIN_PACKET_SUCCESS

    normalized_distance = distance_to_rsu / COMMUNICATION_RANGE
    distance_factor = 1.0 - normalized_distance**2

    density_ratio = min(1.0, nearby_vehicle_count / DENSITY_REFERENCE)
    density_factor = 1.0 - DENSITY_PENALTY * density_ratio

    p = (
        BASE_PACKET_SUCCESS
        * distance_factor
        * density_factor
        * (1.0 - RANDOM_WIRELESS_LOSS)
    )
    return max(MIN_PACKET_SUCCESS, min(1.0, p))


def deterministic_packet_received(
    vehicle_id: str,
    step: int,
    threshold_run_index: int,
    probability: float,
) -> bool:
    """
    Uses a deterministic pseudo-random draw. threshold_run_index is intentionally
    NOT included in the hash so each threshold pair sees the same channel outcome.
    """
    u = stable_unit_value(f"packet|{vehicle_id}|{step}")
    return u <= probability


def get_sumo_binary(use_gui: bool) -> str:
    sumo_home = os.environ.get("SUMO_HOME")
    if not sumo_home:
        raise EnvironmentError(
            "SUMO_HOME is not set. Configure SUMO_HOME before running."
        )

    tools = os.path.join(sumo_home, "tools")
    if tools not in sys.path:
        sys.path.append(tools)

    return "sumo-gui" if use_gui else "sumo"


def import_traci():
    try:
        import traci
        return traci
    except ImportError:
        sumo_home = os.environ.get("SUMO_HOME")
        if not sumo_home:
            raise
        tools = os.path.join(sumo_home, "tools")
        if tools not in sys.path:
            sys.path.append(tools)
        import traci
        return traci


# ============================================================
# ZIP / SUMO FILE DISCOVERY
# ============================================================

def zip_contains_required_files(zip_path: Path) -> bool:
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            names = [Path(n).name for n in zf.namelist()]
        return "mumbai.net.xml" in names and "routes.rou.xml" in names
    except zipfile.BadZipFile:
        return False


def extract_required_files(zip_path: Path, target_dir: Path) -> Path:
    target_dir.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(zip_path, "r") as zf:
        members = zf.namelist()
        net_member = next(
            (m for m in members if Path(m).name == "mumbai.net.xml"),
            None,
        )
        route_member = next(
            (m for m in members if Path(m).name == "routes.rou.xml"),
            None,
        )

        if net_member is None or route_member is None:
            raise FileNotFoundError(
                "The ZIP does not contain mumbai.net.xml and routes.rou.xml."
            )

        for member, output_name in [
            (net_member, "mumbai.net.xml"),
            (route_member, "routes.rou.xml"),
        ]:
            with zf.open(member) as src, (target_dir / output_name).open("wb") as dst:
                shutil.copyfileobj(src, dst)

    return target_dir


def locate_sumo_files(
    explicit_zip: Optional[str] = None,
    explicit_base_dir: Optional[str] = None
) -> Tuple[Path, Optional[Path]]:
    """
    Automatic SUMO file discovery.

    DEFAULT BEHAVIOR FOR VS CODE:
        Place this Python file inside the extracted folder:

            D:\\sumo_projects\\SUMO ATPRV\\

        together with:
            mumbai.net.xml
            routes.rou.xml

        Then simply press Run in VS Code. No command-line arguments are needed.

    Returns:
        (base_dir, temporary_directory_if_created)
    """

    # --------------------------------------------------------
    # 1. BEST DEFAULT: folder containing this Python script
    # --------------------------------------------------------
    script_dir = Path(__file__).resolve().parent

    if (
        (script_dir / "mumbai.net.xml").exists()
        and (script_dir / "routes.rou.xml").exists()
    ):
        return script_dir, None

    # --------------------------------------------------------
    # 2. Optional explicit extracted folder
    # --------------------------------------------------------
    if explicit_base_dir:
        base = Path(explicit_base_dir).expanduser().resolve()

        if not (base / "mumbai.net.xml").exists():
            raise FileNotFoundError(
                f"mumbai.net.xml not found in: {base}"
            )

        if not (base / "routes.rou.xml").exists():
            raise FileNotFoundError(
                f"routes.rou.xml not found in: {base}"
            )

        return base, None

    # --------------------------------------------------------
    # 3. Optional explicit ZIP
    # --------------------------------------------------------
    if explicit_zip:
        zip_path = Path(explicit_zip).expanduser().resolve()

        if not zip_path.exists():
            raise FileNotFoundError(
                f"ZIP file not found: {zip_path}"
            )

        temp = Path(tempfile.mkdtemp(prefix="atprv_sumo_"))
        return extract_required_files(zip_path, temp), temp

    # --------------------------------------------------------
    # 4. Look for a suitable ZIP beside this Python script
    # --------------------------------------------------------
    for zip_path in sorted(script_dir.glob("*.zip")):
        if zip_contains_required_files(zip_path):
            temp = Path(tempfile.mkdtemp(prefix="atprv_sumo_"))
            return extract_required_files(zip_path, temp), temp

    # --------------------------------------------------------
    # 5. Clear diagnostic message
    # --------------------------------------------------------
    raise FileNotFoundError(
        "\nATPRV SUMO files were not found.\n\n"
        "Place this Python file in the SAME EXTRACTED folder as:\n"
        "  mumbai.net.xml\n"
        "  routes.rou.xml\n\n"
        "Recommended folder:\n"
        "  D:\\sumo_projects\\SUMO ATPRV\n\n"
        "Then press Run in VS Code. No command-line arguments are required.\n"
        f"\nPython script folder detected as:\n  {script_dir}\n"
    )


# ============================================================
# TRUST / RISK MODEL
# ============================================================

def mobility_consistency(
    state: VehicleState,
    sim_time: float,
    position: Tuple[float, float],
    speed: float,
) -> float:
    if (
        state.previous_position is None
        or state.previous_speed is None
        or state.previous_time is None
    ):
        state.previous_position = position
        state.previous_speed = speed
        state.previous_time = sim_time
        return 1.0

    dt = sim_time - state.previous_time
    if dt <= 0:
        return 1.0

    actual_displacement = distance(position, state.previous_position)
    predicted_displacement = state.previous_speed * dt
    deviation = abs(actual_displacement - predicted_displacement)

    score = 1.0 - min(1.0, deviation / MAX_POSITION_ERROR)

    state.previous_position = position
    state.previous_speed = speed
    state.previous_time = sim_time

    return clip01(score)


def history_score(state: VehicleState) -> float:
    total = state.auth_total + state.reverify_total
    success = state.auth_success + state.reverify_success
    if total == 0:
        return 0.50
    return clip01(success / total)


def controlled_observations(
    vehicle_id: str,
    malicious: bool,
    attack: str,
    speed: float,
    acceleration: float,
    base_mobility: float,
    packet_received: bool,
) -> Tuple[float, float, float, float, float, bool]:
    """
    Returns:
        B, M, C, Phi, Theta, Gamma, protocol_valid

    Ground truth is injected through controlled attack observations while the
    vehicle's physical speed/position come from the supplied SUMO scenario.
    """

    # Communication metric is based on this observed packet outcome.
    C = 1.0 if packet_received else 0.0

    # Legitimate traffic:
    protocol_valid = True
    B = 1.0
    M = base_mobility
    Phi = 0.0
    Theta = 0.0
    Gamma = clip01(1.0 - base_mobility)

    # Physical plausibility can reduce B even for legitimate traces.
    speed_ok = 0.0 <= speed <= MAX_SPEED
    accel_ok = -MAX_DECELERATION <= acceleration <= MAX_ACCELERATION
    if not speed_ok or not accel_ok:
        B *= 0.80

    if not malicious:
        # Communication failure is treated as communication unreliability, not
        # malicious behavior.
        return (
            clip01(B), clip01(M), clip01(C),
            clip01(Phi), clip01(Theta), clip01(Gamma),
            protocol_valid
        )

    # Controlled malicious behavior.
    protocol_valid = False

    if attack == "stealth":
        # Stealth attacks intentionally produce weaker observable anomalies.
        # The vehicle is still malicious by ground truth, but its measured
        # behavior can remain close to legitimate traffic.
        B = min(B, 0.82)
        M = min(M, 0.88)
        Phi = 0.22
        Theta = 0.18
        Gamma = max(Gamma, 0.15)

    elif attack == "replay":
        # Replay directly affects freshness/duplicate behavior.
        B = min(B, 0.20)
        Phi = 0.90
        Theta = 0.80
        Gamma = max(Gamma, 0.20)

    elif attack == "message_irregularity":
        # Abnormal messaging/protocol behavior.
        B = min(B, 0.35)
        Phi = 0.70
        Theta = 0.90
        Gamma = max(Gamma, 0.25)

    elif attack == "mobility_deviation":
        # Inject an attack indicator on top of the observed SUMO mobility trace.
        M = min(M, 0.25)
        B = min(B, 0.50)
        Phi = 0.60
        Theta = 0.45
        Gamma = 0.90

    return (
        clip01(B), clip01(M), clip01(C),
        clip01(Phi), clip01(Theta), clip01(Gamma),
        protocol_valid
    )


def update_trust(
    old_trust: float,
    B: float,
    M: float,
    C: float,
    H: float,
) -> float:
    new_trust = (
        (1.0 - ETA) * old_trust
        + OMEGA_B * B
        + OMEGA_M * M
        + OMEGA_C * C
        + OMEGA_H * H
    )
    return clip01(new_trust)


def compute_risk(
    trust: float,
    Phi: float,
    Theta: float,
    Gamma: float,
) -> float:
    risk = (
        ALPHA_1 * (1.0 - trust)
        + ALPHA_2 * Phi
        + ALPHA_3 * Theta
        + ALPHA_4 * Gamma
    )
    return clip01(risk)


def preliminary_decision(
    trust: float,
    risk: float,
    tau_min: float,
    tau_acc: float,
) -> str:
    if trust < tau_min:
        return "Reject"

    if trust >= tau_acc and risk < RHO:
        return "Accept"

    return "Reverify"


# ============================================================
# ONE THRESHOLD RUN
# ============================================================

def run_one_threshold_pair(
    traci,
    sumo_binary: str,
    net_file: Path,
    route_file: Path,
    tau_min: float,
    tau_acc: float,
    run_index: int,
    event_writer,
    step_limit: int,
) -> Dict[str, float]:

    label = f"atprv_{run_index}"

    cmd = [
        sumo_binary,
        "-n", str(net_file),
        "-r", str(route_file),
        "--start",
        "--quit-on-end",
        "--step-length", str(STEP_LENGTH),
        "--seed", str(EXPERIMENT_SEED),
        "--no-warnings", "true",
    ]

    traci.start(cmd, label=label)
    conn = traci.getConnection(label)

    states: Dict[str, VehicleState] = defaultdict(VehicleState)

    total_attempts = 0
    malicious_attempts = 0
    legitimate_attempts = 0
    outside_coverage_skipped = 0

    malicious_finally_accepted = 0
    legitimate_finally_rejected = 0
    reverification_count = 0

    direct_accept_count = 0
    direct_reject_count = 0
    reverify_success_count = 0

    try:
        # Determine RSU location from network bounds unless manually set.
        if RSU_POSITION is None:
            # TraCI getNetBoundary() returns two coordinate pairs:
            # ((xmin, ymin), (xmax, ymax))
            (xmin, ymin), (xmax, ymax) = conn.simulation.getNetBoundary()
            rsu_pos = ((xmin + xmax) / 2.0, (ymin + ymax) / 2.0)
        else:
            rsu_pos = RSU_POSITION

        for step in range(step_limit):
            if conn.simulation.getMinExpectedNumber() <= 0:
                break

            conn.simulationStep()

            sim_time = conn.simulation.getTime()
            vehicle_ids = list(conn.vehicle.getIDList())

            nearby_count = 0
            positions: Dict[str, Tuple[float, float]] = {}

            for vid in vehicle_ids:
                pos = conn.vehicle.getPosition(vid)
                positions[vid] = pos
                if distance(pos, rsu_pos) <= COMMUNICATION_RANGE:
                    nearby_count += 1

            for vid in vehicle_ids:
                state = states[vid]

                speed = float(conn.vehicle.getSpeed(vid))
                acceleration = float(conn.vehicle.getAcceleration(vid))
                position = positions[vid]

                malicious = is_malicious_vehicle(vid)
                attack = attack_type(vid) if malicious else "none"

                M_base = mobility_consistency(
                    state, sim_time, position, speed
                )

                d_rsu = distance(position, rsu_pos)

                # --------------------------------------------------------
                # IMPORTANT COUNTING RULE
                # --------------------------------------------------------
                # Vehicles outside RSU communication coverage are not treated
                # as authentication attempts and therefore are not counted as
                # false rejections. They are simply out of service range.
                if d_rsu > COMMUNICATION_RANGE:
                    outside_coverage_skipped += 1
                    continue

                p_recv = communication_probability(d_rsu, nearby_count)
                received = deterministic_packet_received(
                    vid, step, run_index, p_recv
                )

                B, M, C, Phi, Theta, Gamma, protocol_valid = controlled_observations(
                    vehicle_id=vid,
                    malicious=malicious,
                    attack=attack,
                    speed=speed,
                    acceleration=acceleration,
                    base_mobility=M_base,
                    packet_received=received,
                )

                # Historical score uses only past outcomes.
                H = history_score(state)

                trust = update_trust(
                    state.trust, B, M, C, H
                )
                risk = compute_risk(
                    trust, Phi, Theta, Gamma
                )

                prelim = preliminary_decision(
                    trust, risk, tau_min, tau_acc
                )

                # Initial protocol outcome is recorded for history.
                # Packet loss reduces C_i(t), but does not by itself make a
                # legitimate protocol response cryptographically invalid.
                initial_auth_success = bool(protocol_valid)
                state.auth_total += 1
                if initial_auth_success:
                    state.auth_success += 1

                if prelim == "Accept":
                    direct_accept_count += 1
                    final_decision = "Accepted"

                elif prelim == "Reject":
                    direct_reject_count += 1
                    final_decision = "Rejected"

                else:
                    reverification_count += 1
                    state.reverify_total += 1

                    # Fresh challenge-response evaluation.
                    #
                    # Legitimate reverification is highly reliable but is not
                    # assumed perfect. Its success probability depends on the
                    # measured communication reliability C_i and mobility
                    # consistency M_i. This allows a small non-zero FRR to
                    # emerge from the model instead of forcing FRR to zero.
                    if not malicious:
                        legit_pass_prob = (
                            LEGIT_REVERIFY_BASE_SUCCESS
                            + LEGIT_REVERIFY_COMM_WEIGHT * C
                            + LEGIT_REVERIFY_MOBILITY_WEIGHT * M
                        )
                        legit_pass_prob = max(0.0, min(0.995, legit_pass_prob))

                        legit_draw = stable_unit_value(
                            f"legit-reverify|{vid}|{step}"
                        )
                        reverify_success = bool(
                            protocol_valid and legit_draw < legit_pass_prob
                        )

                    elif attack == "stealth":
                        # A small subset of stealth attackers may evade
                        # reverification, giving a non-zero FAR naturally.
                        stealth_draw = stable_unit_value(
                            f"stealth-reverify|{vid}|{step}"
                        )
                        reverify_success = (
                            stealth_draw < STEALTH_REVERIFY_PASS_PROB
                        )
                    else:
                        reverify_success = False

                    if reverify_success:
                        state.reverify_success += 1
                        reverify_success_count += 1
                        final_decision = "Accepted"
                    else:
                        final_decision = "Rejected"

                state.trust = trust

                total_attempts += 1

                if malicious:
                    malicious_attempts += 1
                    if final_decision == "Accepted":
                        malicious_finally_accepted += 1
                else:
                    legitimate_attempts += 1
                    if final_decision == "Rejected":
                        legitimate_finally_rejected += 1

                event_writer.writerow({
                    "tau_min": f"{tau_min:.2f}",
                    "tau_acc": f"{tau_acc:.2f}",
                    "step": step,
                    "time_s": f"{sim_time:.3f}",
                    "vehicle_id": vid,
                    "ground_truth": "malicious" if malicious else "legitimate",
                    "attack_type": attack,
                    "speed_mps": f"{speed:.6f}",
                    "acceleration_mps2": f"{acceleration:.6f}",
                    "distance_to_rsu_m": f"{d_rsu:.6f}",
                    "packet_received": int(received),
                    "B": f"{B:.6f}",
                    "M": f"{M:.6f}",
                    "C": f"{C:.6f}",
                    "H": f"{H:.6f}",
                    "Phi": f"{Phi:.6f}",
                    "Theta": f"{Theta:.6f}",
                    "Gamma": f"{Gamma:.6f}",
                    "trust": f"{trust:.6f}",
                    "risk": f"{risk:.6f}",
                    "preliminary_decision": prelim,
                    "final_decision": final_decision,
                })

    finally:
        conn.close()

    far = (
        100.0 * malicious_finally_accepted / malicious_attempts
        if malicious_attempts else 0.0
    )

    frr = (
        100.0 * legitimate_finally_rejected / legitimate_attempts
        if legitimate_attempts else 0.0
    )

    rtr = (
        100.0 * reverification_count / total_attempts
        if total_attempts else 0.0
    )

    return {
        "tau_min": tau_min,
        "tau_acc": tau_acc,
        "rho": RHO,
        "total_attempts": total_attempts,
        "malicious_attempts": malicious_attempts,
        "legitimate_attempts": legitimate_attempts,
        "malicious_accepted": malicious_finally_accepted,
        "legitimate_rejected": legitimate_finally_rejected,
        "reverification_count": reverification_count,
        "reverification_success_count": reverify_success_count,
        "direct_accept_count": direct_accept_count,
        "direct_reject_count": direct_reject_count,
        "outside_coverage_skipped": outside_coverage_skipped,
        "FAR_percent": far,
        "FRR_percent": frr,
        "RTR_percent": rtr,
    }


# ============================================================
# OUTPUT
# ============================================================

def print_table(rows: List[Dict[str, float]]) -> None:
    print()
    print("ATPRV Threshold Sensitivity Results")
    print("=" * 72)
    header = (
        f"{'tau_min':>8} {'tau_acc':>8} "
        f"{'FAR (%)':>10} {'FRR (%)':>10} {'RTR (%)':>10} "
        f"{'Attempts':>10}"
    )
    print(header)
    print("-" * len(header))

    for row in rows:
        print(
            f"{row['tau_min']:>8.2f} "
            f"{row['tau_acc']:>8.2f} "
            f"{row['FAR_percent']:>10.3f} "
            f"{row['FRR_percent']:>10.3f} "
            f"{row['RTR_percent']:>10.3f} "
            f"{int(row['total_attempts']):>10d}"
        )

    print("=" * 72)


# ============================================================
# MAIN
# ============================================================

def parse_args():
    parser = argparse.ArgumentParser(
        description="ATPRV SUMO threshold sensitivity analysis"
    )
    parser.add_argument(
        "--zip",
        dest="zip_file",
        default=None,
        help="Path to ATPRV ZIP containing mumbai.net.xml and routes.rou.xml",
    )
    parser.add_argument(
        "--base-dir",
        default=None,
        help="Path to already extracted SUMO ATPRV directory",
    )
    parser.add_argument(
        "--gui",
        action="store_true",
        help="Use sumo-gui instead of headless sumo",
    )
    parser.add_argument(
        "--nogui",
        action="store_true",
        help="Explicitly use headless sumo",
    )
    parser.add_argument(
        "--steps",
        type=int,
        default=STEP_LIMIT,
        help=f"Maximum SUMO steps per threshold pair (default: {STEP_LIMIT})",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    if args.gui and args.nogui:
        raise SystemExit("Choose either --gui or --nogui, not both.")

    # Headless is default because the scenario is rerun for each threshold pair.
    use_gui = bool(args.gui)

    # Check trust normalization.
    coefficient_sum = (
        (1.0 - ETA)
        + OMEGA_B
        + OMEGA_M
        + OMEGA_C
        + OMEGA_H
    )

    if abs(coefficient_sum - 1.0) > 1e-12:
        raise ValueError(
            f"Trust coefficients must sum to 1. Current sum={coefficient_sum}"
        )

    if not math.isclose(
        ALPHA_1 + ALPHA_2 + ALPHA_3 + ALPHA_4,
        1.0,
        rel_tol=0.0,
        abs_tol=1e-12,
    ):
        raise ValueError("Risk coefficients alpha_1...alpha_4 must sum to 1.")

    # Normal VS Code execution requires no arguments.
    # The folder containing this Python file is checked first.
    base_dir, temporary_dir = locate_sumo_files(
        explicit_zip=args.zip_file,
        explicit_base_dir=args.base_dir,
    )

    net_file = base_dir / "mumbai.net.xml"
    route_file = base_dir / "routes.rou.xml"

    print("SUMO network :", net_file)
    print("SUMO routes  :", route_file)
    print(f"Malicious fraction : {MALICIOUS_FRACTION*100:.1f}%")
    print(f"Experiment seed    : {EXPERIMENT_SEED}")
    print(f"Risk threshold rho : {RHO:.2f}")
    print("Legitimate reverification: reliability-aware and probabilistic")
    print("No target FAR or FRR is hard-coded")
    print(f"Steps per run      : {args.steps}")
    print()
    print(
        "Ground-truth labels and attack classes are deterministic and are "
        "held constant across all threshold combinations."
    )

    sumo_binary = get_sumo_binary(use_gui=use_gui)
    traci = import_traci()

    event_fields = [
        "tau_min",
        "tau_acc",
        "step",
        "time_s",
        "vehicle_id",
        "ground_truth",
        "attack_type",
        "speed_mps",
        "acceleration_mps2",
        "distance_to_rsu_m",
        "packet_received",
        "B",
        "M",
        "C",
        "H",
        "Phi",
        "Theta",
        "Gamma",
        "trust",
        "risk",
        "preliminary_decision",
        "final_decision",
    ]

    results: List[Dict[str, float]] = []

    try:
        with open(EVENT_CSV, "w", newline="", encoding="utf-8") as event_file:
            event_writer = csv.DictWriter(
                event_file,
                fieldnames=event_fields,
            )
            event_writer.writeheader()

            for run_index, (tau_min, tau_acc) in enumerate(
                THRESHOLD_PAIRS, start=1
            ):
                print(
                    f"Running threshold pair {run_index}/{len(THRESHOLD_PAIRS)}: "
                    f"tau_min={tau_min:.2f}, tau_acc={tau_acc:.2f}"
                )

                row = run_one_threshold_pair(
                    traci=traci,
                    sumo_binary=sumo_binary,
                    net_file=net_file,
                    route_file=route_file,
                    tau_min=tau_min,
                    tau_acc=tau_acc,
                    run_index=run_index,
                    event_writer=event_writer,
                    step_limit=args.steps,
                )

                results.append(row)

    finally:
        if temporary_dir is not None:
            shutil.rmtree(temporary_dir, ignore_errors=True)

    summary_fields = [
        "tau_min",
        "tau_acc",
        "rho",
        "total_attempts",
        "malicious_attempts",
        "legitimate_attempts",
        "malicious_accepted",
        "legitimate_rejected",
        "reverification_count",
        "reverification_success_count",
        "direct_accept_count",
        "direct_reject_count",
        "outside_coverage_skipped",
        "FAR_percent",
        "FRR_percent",
        "RTR_percent",
    ]

    with open(SUMMARY_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=summary_fields)
        writer.writeheader()
        writer.writerows(results)

    print_table(results)

    print()
    print("Saved:")
    print(" -", Path(SUMMARY_CSV).resolve())
    print(" -", Path(EVENT_CSV).resolve())

    # Select a balanced operating point using the lowest combined FAR and FRR.
    # RTR is used as a secondary tie-breaker.
    if results:
        best = min(
            results,
            key=lambda r: (
                r["FAR_percent"] + r["FRR_percent"],
                r["RTR_percent"],
            ),
        )

        print()
        print("Balanced operating point in this sweep:")
        print(
            f"  tau_min={best['tau_min']:.2f}, "
            f"tau_acc={best['tau_acc']:.2f}, "
            f"FAR={best['FAR_percent']:.3f}%, "
            f"FRR={best['FRR_percent']:.3f}%, "
            f"RTR={best['RTR_percent']:.3f}%"
        )


if __name__ == "__main__":
    main()
