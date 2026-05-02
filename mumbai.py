import os
import sys
import csv
import math
from pathlib import Path
from typing import Dict, List

import traci


# =========================================================
# SUMO Settings
# =========================================================
SUMO_GUI = True
NET_FILE = "mumbai.net.xml"
ROUTE_FILE = "routes.rou.xml"
OUTPUT_CSV = "proposed_work_log.csv"
STEP_LIMIT = 1000


# =========================================================
# YOUR CRYPTO COSTS (ms)
# =========================================================
T_pm = 0.3385
T_pa = 0.0872
T_rnd = 0.0675
T_sm = 0.0278
T_h = 0.4758


def auth_cost():
    return T_pm + T_rnd + T_h + T_sm + T_pa


def rev_cost():
    return T_pm + T_rnd + 4*T_h + T_sm + 2*T_pa


# =========================================================
# TRUST MODEL PARAMETERS
# =========================================================
eta = 0.2
w1 = w2 = w3 = w4 = 0.2

a1 = a2 = a3 = a4 = 0.25

tau_acc = 0.75
tau_min = 0.40
rho = 0.45


# =========================================================
# VEHICLE STATE
# =========================================================
class VehicleState:
    def __init__(self):
        self.trust = 0.6
        self.last_seen = -1


# =========================================================
# SUMO Setup
# =========================================================
def get_sumo_binary():
    sumo_home = os.environ.get("SUMO_HOME")
    if not sumo_home:
        raise EnvironmentError("SUMO_HOME not set")
    tools = os.path.join(sumo_home, "tools")
    sys.path.append(tools)
    return "sumo-gui" if SUMO_GUI else "sumo"


# =========================================================
# MAIN SIMULATION
# =========================================================
def run():

    sumo_binary = get_sumo_binary()

    traci.start([
        sumo_binary,
        "-n", NET_FILE,
        "-r", ROUTE_FILE,
        "--start",
        "--quit-on-end"
    ])

    vehicle_states: Dict[str, VehicleState] = {}

    rows = []

    total_cost = 0

    for step in range(STEP_LIMIT):

        traci.simulationStep()

        veh_ids = traci.vehicle.getIDList()

        rev_count = 0
        accept_count = 0
        reject_count = 0

        speeds = []

        for vid in veh_ids:

            speed = traci.vehicle.getSpeed(vid)
            speeds.append(speed)

            if vid not in vehicle_states:
                vehicle_states[vid] = VehicleState()

            state = vehicle_states[vid]

            # =====================================================
            # Generate Behaviour Features
            # =====================================================
            B = min(1, speed / 15)                      # behaviour
            M = min(1, speed / 20)                      # mobility
            C = 0.8                                    # communication
            H = state.trust                            # history

            Phi = 1 - B                                # anomaly
            Theta = abs(speed - 10)/10
            Gamma = abs(speed - 8)/10

            # =====================================================
            # TRUST UPDATE
            # =====================================================
            T_new = (
                (1-eta)*state.trust +
                w1*B + w2*M + w3*C + w4*H
            )

            T_new = max(0, min(1, T_new))

            # =====================================================
            # RISK COMPUTATION
            # =====================================================
            R = (
                a1*(1 - T_new) +
                a2*Phi +
                a3*Theta +
                a4*Gamma
            )

            R = max(0, min(1, R))

            # =====================================================
            # DECISION
            # =====================================================
            if T_new >= tau_acc and R < rho:
                decision = "Accept"
                accept_count += 1
                total_cost += auth_cost()

            elif T_new < tau_min:
                decision = "Reject"
                reject_count += 1

            else:
                decision = "Reverify"
                rev_count += 1
                total_cost += rev_cost()

            state.trust = T_new
            state.last_seen = step

        # =====================================================
        # SYSTEM METRICS
        # =====================================================
        avg_speed = sum(speeds)/len(speeds) if speeds else 0

        rows.append({
            "step": step,
            "vehicles": len(veh_ids),
            "avg_speed": round(avg_speed, 4),
            "accept": accept_count,
            "reverify": rev_count,
            "reject": reject_count,
            "total_cost_ms": round(total_cost, 4)
        })

    traci.close()

    # =====================================================
    # SAVE OUTPUT
    # =====================================================
    with open(OUTPUT_CSV, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

    print("Simulation completed")
    print("Output:", OUTPUT_CSV)


if __name__ == "__main__":
    run()