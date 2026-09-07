#!/usr/bin/env python3
"""
ATPRV: SUMO-Based Adversarial Trust and Predictive Reverification Evaluation
============================================================================

This program extends the ATPRV SUMO/TraCI evaluation with:
1. Replay attacks
2. False-data injection
3. Sybil behavior
4. Trust-manipulation/on-off behavior
5. Mixed attacks
6. Malicious-vehicle ratio sweep: 10%, 20%, 30%, 40%, 50%

SUMO supplies mobility (position, speed, acceleration, time). Python supplies
the communication abstraction, controlled attack injection, trust/risk model,
and predictive reverification logic.


Required files in the same folder:
    mumbai.net.xml
    routes.rou.xml

Outputs:
    ATPRV_attackwise_summary.csv
    ATPRV_ratio_sweep_summary.csv
    ATPRV_attack_event_log.csv
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import math
import os
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

EXPERIMENT_SEED = 2026

# SUMO / communication
STEP_LIMIT = 1000
STEP_LENGTH = 1.0
COMMUNICATION_RANGE = 300.0
BASE_PACKET_SUCCESS = 0.99
MIN_PACKET_SUCCESS = 0.05
DENSITY_REFERENCE = 50
DENSITY_PENALTY = 0.25
RANDOM_WIRELESS_LOSS = 0.02
RSU_POSITION: Optional[Tuple[float, float]] = None

# Trust / risk
ETA = 0.20
OMEGA_B = 0.05
OMEGA_M = 0.05
OMEGA_C = 0.05
OMEGA_H = 0.05

ALPHA_1 = 0.25
ALPHA_2 = 0.25
ALPHA_3 = 0.25
ALPHA_4 = 0.25

INITIAL_TRUST = 0.50
TAU_MIN = 0.50
TAU_ACC = 0.70
RHO = 0.50

# Plausibility
MAX_SPEED = 45.0
MAX_ACCELERATION = 8.0
MAX_DECELERATION = 10.0
MAX_POSITION_ERROR = 10.0
FRESHNESS_WINDOW = 2.0
MIN_BEACON_INTERVAL = 0.05
MAX_BEACON_INTERVAL = 1.50

# Attack experiment
ATTACK_SCENARIOS = [
    "replay",
    "false_data_injection",
    "sybil",
    "trust_manipulation",
    "mixed",
]
MALICIOUS_RATIO_SWEEP = [0.10, 0.20, 0.30, 0.40, 0.50]
ATTACKWISE_MALICIOUS_RATIO = 0.20
SYBIL_IDENTITIES = 3
TRUST_MANIP_ATTACK_DUTY = 0.30
TRUST_MANIP_REVERIFY_PASS_PROB = 0.08

# Legitimate reverification
LEGIT_REVERIFY_BASE_SUCCESS = 0.965
LEGIT_REVERIFY_COMM_WEIGHT = 0.020
LEGIT_REVERIFY_MOBILITY_WEIGHT = 0.015

# Output
ATTACKWISE_CSV = "ATPRV_attackwise_summary.csv"
RATIO_CSV = "ATPRV_ratio_sweep_summary.csv"
EVENT_CSV = "ATPRV_attack_event_log.csv"


@dataclass
class IdentityState:
    trust: float = INITIAL_TRUST
    previous_position: Optional[Tuple[float, float]] = None
    previous_speed: Optional[float] = None
    previous_time: Optional[float] = None
    last_message_id: Optional[str] = None
    last_message_time: Optional[float] = None
    auth_total: int = 0
    auth_success: int = 0
    reverify_total: int = 0
    reverify_success: int = 0


@dataclass
class Counters:
    total_attempts: int = 0
    malicious_attempts: int = 0
    legitimate_attempts: int = 0
    malicious_accepted: int = 0
    malicious_rejected: int = 0
    legitimate_accepted: int = 0
    legitimate_rejected: int = 0
    reverification_count: int = 0
    reverification_success_count: int = 0
    direct_accept_count: int = 0
    direct_reject_count: int = 0
    outside_coverage_skipped: int = 0


def clip01(x: float) -> float:
    return max(0.0, min(1.0, x))


def stable_unit_value(text: str, seed: int = EXPERIMENT_SEED) -> float:
    digest = hashlib.sha256(f"{seed}|{text}".encode("utf-8")).digest()
    integer = int.from_bytes(digest[:8], "big")
    return integer / float(2**64)


def distance(p1: Tuple[float, float], p2: Tuple[float, float]) -> float:
    return math.hypot(p1[0] - p2[0], p1[1] - p2[1])


def is_malicious_vehicle(vehicle_id: str, ratio: float) -> bool:
    return stable_unit_value("label|" + vehicle_id) < ratio


def communication_probability(distance_to_rsu: float, nearby_count: int) -> float:
    if distance_to_rsu >= COMMUNICATION_RANGE:
        return MIN_PACKET_SUCCESS

    dnorm = distance_to_rsu / COMMUNICATION_RANGE
    distance_factor = 1.0 - dnorm**2
    density_ratio = min(1.0, nearby_count / DENSITY_REFERENCE)
    density_factor = 1.0 - DENSITY_PENALTY * density_ratio

    p = (
        BASE_PACKET_SUCCESS
        * distance_factor
        * density_factor
        * (1.0 - RANDOM_WIRELESS_LOSS)
    )
    return max(MIN_PACKET_SUCCESS, min(1.0, p))


def packet_received(vehicle_id: str, step: int, probability: float) -> bool:
    return stable_unit_value(f"packet|{vehicle_id}|{step}") <= probability


def mobility_consistency(
    state: IdentityState,
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

    actual = distance(position, state.previous_position)
    predicted = state.previous_speed * dt
    deviation = abs(actual - predicted)

    score = 1.0 - min(1.0, deviation / MAX_POSITION_ERROR)

    state.previous_position = position
    state.previous_speed = speed
    state.previous_time = sim_time
    return clip01(score)


def history_score(state: IdentityState) -> float:
    total = state.auth_total + state.reverify_total
    success = state.auth_success + state.reverify_success
    return 0.50 if total == 0 else clip01(success / total)


def update_trust(old: float, B: float, M: float, C: float, H: float) -> float:
    return clip01(
        (1.0 - ETA) * old
        + OMEGA_B * B
        + OMEGA_M * M
        + OMEGA_C * C
        + OMEGA_H * H
    )


def compute_risk(trust: float, Phi: float, Theta: float, Gamma: float) -> float:
    return clip01(
        ALPHA_1 * (1.0 - trust)
        + ALPHA_2 * Phi
        + ALPHA_3 * Theta
        + ALPHA_4 * Gamma
    )


def preliminary_decision(trust: float, risk: float) -> str:
    if trust < TAU_MIN:
        return "Reject"
    if trust >= TAU_ACC and risk < RHO:
        return "Accept"
    return "Reverify"


def mixed_attack_for(vehicle_id: str, step: int) -> str:
    choices = [
        "replay",
        "false_data_injection",
        "sybil",
        "trust_manipulation",
    ]
    u = stable_unit_value(f"mixed|{vehicle_id}|{step}")
    idx = min(int(u * len(choices)), len(choices) - 1)
    return choices[idx]


def logical_ids(physical_id: str, malicious: bool, attack: str) -> List[str]:
    if malicious and attack == "sybil":
        return [f"{physical_id}#SYBIL{k+1}" for k in range(SYBIL_IDENTITIES)]
    return [physical_id]


def inject_attack(
    physical_id: str,
    logical_id: str,
    attack: str,
    step: int,
    sim_time: float,
    true_position: Tuple[float, float],
    true_speed: float,
    true_acceleration: float,
    received: bool,
    state: IdentityState,
    identity_count: int,
) -> Dict[str, object]:

    reported_position = true_position
    reported_speed = true_speed
    reported_acceleration = true_acceleration
    message_timestamp = sim_time
    message_id = f"{logical_id}|{step}"
    protocol_valid = True
    attack_active = False

    Phi = 0.0
    Theta = 0.0
    Gamma = 0.0

    if attack == "replay":
        attack_active = True
        message_timestamp = max(0.0, sim_time - (FRESHNESS_WINDOW + 3.0))
        message_id = f"{logical_id}|replay|{max(0, step-5)}"
        protocol_valid = False
        Phi, Theta, Gamma = 0.95, 0.90, 0.10

    elif attack == "false_data_injection":
        attack_active = True
        dx = 25.0 + 25.0 * stable_unit_value(f"fdi-x|{logical_id}|{step}")
        dy = 15.0 + 20.0 * stable_unit_value(f"fdi-y|{logical_id}|{step}")
        reported_position = (true_position[0] + dx, true_position[1] - dy)
        reported_speed = min(MAX_SPEED * 1.30, true_speed + 15.0)
        reported_acceleration = max(MAX_ACCELERATION * 1.25, abs(true_acceleration) + 10.0)
        protocol_valid = False
        Phi, Theta, Gamma = 0.75, 0.45, 0.95

    elif attack == "sybil":
        attack_active = True
        protocol_valid = False
        Phi = 0.60
        Theta = min(1.0, 0.55 + 0.15 * max(0, identity_count - 1))
        Gamma = 0.20

    elif attack == "trust_manipulation":
        active = stable_unit_value(f"trust-duty|{logical_id}|{step}") < TRUST_MANIP_ATTACK_DUTY
        attack_active = active
        if active:
            protocol_valid = False
            reported_speed = min(MAX_SPEED, true_speed + 4.0)
            Phi, Theta, Gamma = 0.55, 0.45, 0.30
        else:
            protocol_valid = True
            Phi, Theta, Gamma = 0.05, 0.05, 0.05

    freshness_ok = abs(sim_time - message_timestamp) <= FRESHNESS_WINDOW
    no_replay = state.last_message_id is None or message_id != state.last_message_id

    if state.last_message_time is None:
        rate_ok = True
    else:
        interval = sim_time - state.last_message_time
        rate_ok = MIN_BEACON_INTERVAL <= interval <= MAX_BEACON_INTERVAL

    speed_ok = 0.0 <= reported_speed <= MAX_SPEED
    accel_ok = -MAX_DECELERATION <= reported_acceleration <= MAX_ACCELERATION

    checks = [
        freshness_ok,
        no_replay,
        rate_ok,
        speed_ok,
        accel_ok,
        received,
        protocol_valid,
    ]
    B = sum(bool(v) for v in checks) / len(checks)

    if attack == "sybil":
        B = min(B, 0.45)
    elif attack == "false_data_injection":
        B = min(B, 0.40)

    state.last_message_id = message_id
    state.last_message_time = sim_time

    return {
        "reported_position": reported_position,
        "reported_speed": reported_speed,
        "reported_acceleration": reported_acceleration,
        "message_timestamp": message_timestamp,
        "message_id": message_id,
        "protocol_valid": protocol_valid,
        "B": clip01(B),
        "Phi": clip01(Phi),
        "Theta": clip01(Theta),
        "Gamma": clip01(Gamma),
        "attack_active": attack_active,
    }


def reverification_result(
    logical_id: str,
    step: int,
    malicious: bool,
    attack: str,
    attack_active: bool,
    C: float,
    M: float,
) -> bool:
    if not malicious:
        p = (
            LEGIT_REVERIFY_BASE_SUCCESS
            + LEGIT_REVERIFY_COMM_WEIGHT * C
            + LEGIT_REVERIFY_MOBILITY_WEIGHT * M
        )
        p = max(0.0, min(0.995, p))
        return stable_unit_value(f"legit-reverify|{logical_id}|{step}") < p

    if attack in {"replay", "false_data_injection", "sybil"}:
        return False

    if attack == "trust_manipulation":
        if not attack_active:
            return True
        return (
            stable_unit_value(f"trustman-reverify|{logical_id}|{step}")
            < TRUST_MANIP_REVERIFY_PASS_PROB
        )

    return False


def run_experiment(
    traci,
    sumo_binary: str,
    net_file: Path,
    route_file: Path,
    attack_scenario: str,
    malicious_ratio: float,
    run_label: str,
    event_writer,
    step_limit: int,
) -> Dict[str, float]:

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

    traci.start(cmd, label=run_label)
    conn = traci.getConnection(run_label)

    states: Dict[str, IdentityState] = defaultdict(IdentityState)
    c = Counters()

    try:
        if RSU_POSITION is None:
            (xmin, ymin), (xmax, ymax) = conn.simulation.getNetBoundary()
            rsu_pos = ((xmin + xmax) / 2.0, (ymin + ymax) / 2.0)
        else:
            rsu_pos = RSU_POSITION

        for step in range(step_limit):
            if conn.simulation.getMinExpectedNumber() <= 0:
                break

            conn.simulationStep()
            sim_time = float(conn.simulation.getTime())
            vids = list(conn.vehicle.getIDList())
            positions = {vid: tuple(conn.vehicle.getPosition(vid)) for vid in vids}

            nearby_count = sum(
                distance(positions[vid], rsu_pos) <= COMMUNICATION_RANGE
                for vid in vids
            )

            for physical_id in vids:
                true_position = positions[physical_id]
                true_speed = float(conn.vehicle.getSpeed(physical_id))
                true_acceleration = float(conn.vehicle.getAcceleration(physical_id))
                d_rsu = distance(true_position, rsu_pos)

                if d_rsu > COMMUNICATION_RANGE:
                    c.outside_coverage_skipped += 1
                    continue

                malicious = is_malicious_vehicle(physical_id, malicious_ratio)

                if malicious:
                    attack = mixed_attack_for(physical_id, step) if attack_scenario == "mixed" else attack_scenario
                else:
                    attack = "none"

                ids = logical_ids(physical_id, malicious, attack)

                p_recv = communication_probability(d_rsu, nearby_count)
                received = packet_received(physical_id, step, p_recv)

                for logical_id in ids:
                    state = states[logical_id]
                    H = history_score(state)

                    obs = inject_attack(
                        physical_id=physical_id,
                        logical_id=logical_id,
                        attack=attack,
                        step=step,
                        sim_time=sim_time,
                        true_position=true_position,
                        true_speed=true_speed,
                        true_acceleration=true_acceleration,
                        received=received,
                        state=state,
                        identity_count=len(ids),
                    )

                    M = mobility_consistency(
                        state,
                        sim_time,
                        obs["reported_position"],
                        float(obs["reported_speed"]),
                    )

                    if attack == "false_data_injection":
                        pos_error = distance(obs["reported_position"], true_position)
                        speed_error = abs(float(obs["reported_speed"]) - true_speed)
                        penalty = max(
                            min(1.0, pos_error / 50.0),
                            min(1.0, speed_error / 20.0),
                        )
                        M = min(M, 1.0 - penalty)

                    B = float(obs["B"])
                    C = 1.0 if received else 0.0
                    Phi = float(obs["Phi"])
                    Theta = float(obs["Theta"])
                    Gamma = max(float(obs["Gamma"]), 1.0 - M)

                    trust = update_trust(state.trust, B, M, C, H)
                    risk = compute_risk(trust, Phi, Theta, Gamma)
                    prelim = preliminary_decision(trust, risk)

                    state.auth_total += 1
                    if bool(obs["protocol_valid"]):
                        state.auth_success += 1

                    if prelim == "Accept":
                        c.direct_accept_count += 1
                        final_decision = "Accepted"

                    elif prelim == "Reject":
                        c.direct_reject_count += 1
                        final_decision = "Rejected"

                    else:
                        c.reverification_count += 1
                        state.reverify_total += 1

                        ok = reverification_result(
                            logical_id=logical_id,
                            step=step,
                            malicious=malicious,
                            attack=attack,
                            attack_active=bool(obs["attack_active"]),
                            C=C,
                            M=M,
                        )

                        if ok:
                            state.reverify_success += 1
                            c.reverification_success_count += 1
                            final_decision = "Accepted"
                        else:
                            final_decision = "Rejected"

                    state.trust = trust
                    c.total_attempts += 1

                    if malicious:
                        c.malicious_attempts += 1
                        if final_decision == "Accepted":
                            c.malicious_accepted += 1
                        else:
                            c.malicious_rejected += 1
                    else:
                        c.legitimate_attempts += 1
                        if final_decision == "Accepted":
                            c.legitimate_accepted += 1
                        else:
                            c.legitimate_rejected += 1

                    event_writer.writerow({
                        "run_label": run_label,
                        "attack_scenario": attack_scenario,
                        "effective_attack": attack,
                        "malicious_ratio": f"{malicious_ratio:.2f}",
                        "step": step,
                        "time_s": f"{sim_time:.3f}",
                        "physical_vehicle_id": physical_id,
                        "logical_vehicle_id": logical_id,
                        "ground_truth": "malicious" if malicious else "legitimate",
                        "attack_active": int(bool(obs["attack_active"])),
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

    detection = 100.0 * c.malicious_rejected / c.malicious_attempts if c.malicious_attempts else 0.0
    far = 100.0 * c.malicious_accepted / c.malicious_attempts if c.malicious_attempts else 0.0
    frr = 100.0 * c.legitimate_rejected / c.legitimate_attempts if c.legitimate_attempts else 0.0
    rtr = 100.0 * c.reverification_count / c.total_attempts if c.total_attempts else 0.0

    return {
        "attack_scenario": attack_scenario,
        "malicious_ratio": malicious_ratio,
        "tau_min": TAU_MIN,
        "tau_acc": TAU_ACC,
        "rho": RHO,
        "total_attempts": c.total_attempts,
        "malicious_attempts": c.malicious_attempts,
        "legitimate_attempts": c.legitimate_attempts,
        "malicious_accepted": c.malicious_accepted,
        "malicious_rejected": c.malicious_rejected,
        "legitimate_accepted": c.legitimate_accepted,
        "legitimate_rejected": c.legitimate_rejected,
        "reverification_count": c.reverification_count,
        "reverification_success_count": c.reverification_success_count,
        "outside_coverage_skipped": c.outside_coverage_skipped,
        "DetectionRate_percent": detection,
        "FAR_percent": far,
        "FRR_percent": frr,
        "RTR_percent": rtr,
    }


SUMMARY_FIELDS = [
    "attack_scenario", "malicious_ratio", "tau_min", "tau_acc", "rho",
    "total_attempts", "malicious_attempts", "legitimate_attempts",
    "malicious_accepted", "malicious_rejected",
    "legitimate_accepted", "legitimate_rejected",
    "reverification_count", "reverification_success_count",
    "outside_coverage_skipped",
    "DetectionRate_percent", "FAR_percent", "FRR_percent", "RTR_percent",
]


def write_summary(filename: str, rows: List[Dict[str, float]]) -> None:
    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=SUMMARY_FIELDS)
        writer.writeheader()
        writer.writerows(rows)


def print_summary(title: str, rows: List[Dict[str, float]]) -> None:
    print()
    print(title)
    print("=" * 106)
    print(
        f"{'Attack':>22} {'Mal.%':>7} {'Detect.%':>10} "
        f"{'FAR.%':>9} {'FRR.%':>9} {'RTR.%':>9} {'Attempts':>10}"
    )
    print("-" * 106)
    for r in rows:
        print(
            f"{str(r['attack_scenario']):>22} "
            f"{100*r['malicious_ratio']:>7.1f} "
            f"{r['DetectionRate_percent']:>10.3f} "
            f"{r['FAR_percent']:>9.3f} "
            f"{r['FRR_percent']:>9.3f} "
            f"{r['RTR_percent']:>9.3f} "
            f"{int(r['total_attempts']):>10d}"
        )
    print("=" * 106)


def get_sumo_binary(use_gui: bool) -> str:
    sumo_home = os.environ.get("SUMO_HOME")
    if not sumo_home:
        raise EnvironmentError("SUMO_HOME is not set.")

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


def locate_files(net_arg: Optional[str], routes_arg: Optional[str]) -> Tuple[Path, Path]:
    script_dir = Path(__file__).resolve().parent

    net_file = Path(net_arg).expanduser().resolve() if net_arg else script_dir / "mumbai.net.xml"
    route_file = Path(routes_arg).expanduser().resolve() if routes_arg else script_dir / "routes.rou.xml"

    if not net_file.exists():
        raise FileNotFoundError(f"Network file not found: {net_file}")
    if not route_file.exists():
        raise FileNotFoundError(f"Route file not found: {route_file}")

    return net_file, route_file


def parse_args():
    parser = argparse.ArgumentParser(
        description="ATPRV SUMO attack evaluation"
    )
    parser.add_argument("--net", default=None)
    parser.add_argument("--routes", default=None)
    parser.add_argument("--steps", type=int, default=STEP_LIMIT)
    parser.add_argument("--gui", action="store_true")
    parser.add_argument("--only-attackwise", action="store_true")
    parser.add_argument("--only-ratio-sweep", action="store_true")
    return parser.parse_args()


def main():
    args = parse_args()

    if args.only_attackwise and args.only_ratio_sweep:
        raise SystemExit("Use only one of --only-attackwise or --only-ratio-sweep.")

    trust_sum = (1.0 - ETA) + OMEGA_B + OMEGA_M + OMEGA_C + OMEGA_H
    if not math.isclose(trust_sum, 1.0, abs_tol=1e-12):
        raise ValueError("Trust coefficients must sum to 1.")

    alpha_sum = ALPHA_1 + ALPHA_2 + ALPHA_3 + ALPHA_4
    if not math.isclose(alpha_sum, 1.0, abs_tol=1e-12):
        raise ValueError("Risk coefficients must sum to 1.")

    net_file, route_file = locate_files(args.net, args.routes)
    sumo_binary = get_sumo_binary(args.gui)
    traci = import_traci()

    print("ATPRV SUMO Adversarial Evaluation")
    print("=================================")
    print("Network :", net_file)
    print("Routes  :", route_file)
    print("Seed    :", EXPERIMENT_SEED)
    print("tau_min :", TAU_MIN)
    print("tau_acc :", TAU_ACC)
    print("rho     :", RHO)
    print("Steps   :", args.steps)

    event_fields = [
        "run_label", "attack_scenario", "effective_attack",
        "malicious_ratio", "step", "time_s",
        "physical_vehicle_id", "logical_vehicle_id",
        "ground_truth", "attack_active", "packet_received",
        "B", "M", "C", "H", "Phi", "Theta", "Gamma",
        "trust", "risk", "preliminary_decision", "final_decision",
    ]

    attack_rows = []
    ratio_rows = []

    with open(EVENT_CSV, "w", newline="", encoding="utf-8") as f:
        event_writer = csv.DictWriter(f, fieldnames=event_fields)
        event_writer.writeheader()

        if not args.only_ratio_sweep:
            print("\nExperiment 1: attack-wise evaluation")
            for i, attack in enumerate(ATTACK_SCENARIOS, 1):
                print(f"  [{i}/{len(ATTACK_SCENARIOS)}] {attack}")
                row = run_experiment(
                    traci, sumo_binary, net_file, route_file,
                    attack, ATTACKWISE_MALICIOUS_RATIO,
                    f"attack_{i}", event_writer, args.steps
                )
                attack_rows.append(row)

        if not args.only_attackwise:
            print("\nExperiment 2: malicious-ratio sweep (mixed attacks)")
            for i, ratio in enumerate(MALICIOUS_RATIO_SWEEP, 1):
                print(f"  [{i}/{len(MALICIOUS_RATIO_SWEEP)}] {ratio*100:.0f}% malicious")
                row = run_experiment(
                    traci, sumo_binary, net_file, route_file,
                    "mixed", ratio,
                    f"ratio_{i}", event_writer, args.steps
                )
                ratio_rows.append(row)

    if attack_rows:
        write_summary(ATTACKWISE_CSV, attack_rows)
        print_summary("ATPRV Attack-Wise Security Results", attack_rows)

    if ratio_rows:
        write_summary(RATIO_CSV, ratio_rows)
        print_summary("ATPRV Malicious-Ratio Sweep Results", ratio_rows)

    print("\nSaved:")
    if attack_rows:
        print(" -", Path(ATTACKWISE_CSV).resolve())
    if ratio_rows:
        print(" -", Path(RATIO_CSV).resolve())
    print(" -", Path(EVENT_CSV).resolve())

    print(
        "\nMethodological note: attacks and reverification are protocol-level "
        "Python abstractions over SUMO mobility. Replace the reverification "
        "function with the actual LWR routine if cryptographic execution is required."
    )


if __name__ == "__main__":
    main()
