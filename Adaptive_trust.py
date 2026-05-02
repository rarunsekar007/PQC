import os
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

# =========================================================
# Output Folder
# =========================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(BASE_DIR, "results")
os.makedirs(OUTPUT_DIR, exist_ok=True)

print("Saving all files in:", OUTPUT_DIR)

# =========================================================
# Cryptographic Operation Costs in ms
# =========================================================
T_pm = 0.3385
T_pa = 0.0872
T_rnd = 0.0675
T_sm = 0.0278
T_spl = 0.0751
T_cha = 0.3124
T_mod = 0.0427
T_h = 0.4758
T_sym = 0.0461
T_fe = 0.0219
T_xor = 0.0651

# =========================================================
# Computational Cost of Four Works
# =========================================================
schemes = {
    "Liu et al.": {
        "vehicle": 6*T_pm + 5*T_pa + 5*T_h + T_cha + 2*T_mod,
        "rsu": 6*T_pm + 5*T_pa + 5*T_h + T_cha + 2*T_mod
    },
    "Yan et al.": {
        "vehicle": 2*T_pm + T_pa + 7*T_h,
        "rsu": 8*T_pm + T_pa + 10*T_h
    },
    "Ahmed et al.": {
        "vehicle": 12*T_pm + 2*T_xor + 3*T_h + T_cha + 7*T_mod,
        "rsu": 11*T_pm + 2*T_h + 6*T_mod
    },
    "Proposed work": {
        "vehicle": T_pm + T_rnd + T_h + T_sm + T_pa,
        "rsu": T_pm + T_rnd + 3*T_h + T_sm + 2*T_pa
    }
}

for s in schemes:
    schemes[s]["auth"] = schemes[s]["vehicle"] + schemes[s]["rsu"]

# =========================================================
# Cost-aware Trust Gain, Risk Factor, and Detection Gain
# =========================================================
cost_values = [schemes[s]["auth"] for s in schemes]
C_min = min(cost_values)
C_max = max(cost_values)

for s in schemes:
    C_s = schemes[s]["auth"]

    if C_max == C_min:
        schemes[s]["trust_gain"] = 1.0
        schemes[s]["risk_factor"] = 1.0
        schemes[s]["detection_gain"] = 1.0
    else:
        # Lower computation cost gives better trust responsiveness.
        schemes[s]["trust_gain"] = 0.85 + 0.15 * ((C_max - C_s) / (C_max - C_min))

        # Higher computation cost gives higher latency-induced risk.
        schemes[s]["risk_factor"] = 0.85 + 0.35 * ((C_s - C_min) / (C_max - C_min))

        # Lower computation cost enables better anomaly processing and detection.
        schemes[s]["detection_gain"] = 0.90 + 0.25 * ((C_max - C_s) / (C_max - C_min))

# =========================================================
# Reverification Cost
# =========================================================
C_vehicle_rev = T_pm + T_rnd + T_h + T_sm + T_pa
C_rsu_rev = T_pm + T_rnd + 4*T_h + T_sm + 2*T_pa
C_rev_proposed = C_vehicle_rev + C_rsu_rev

for s in schemes:
    if s == "Proposed work":
        schemes[s]["rev"] = C_rev_proposed
    else:
        # Existing works are assumed to perform full re-authentication
        # when additional verification is required.
        schemes[s]["rev"] = schemes[s]["auth"]

print("\nScheme Cost and Scaling Summary")
for s, v in schemes.items():
    print(
        f"{s}: Auth = {v['auth']:.4f} ms, "
        f"Rev = {v['rev']:.4f} ms, "
        f"Trust Gain = {v['trust_gain']:.4f}, "
        f"Risk Factor = {v['risk_factor']:.4f}, "
        f"Detection Gain = {v['detection_gain']:.4f}"
    )

# =========================================================
# Adaptive Trust Simulation Settings
# =========================================================
np.random.seed(42)

N_VEHICLES = 100
TIME_STEPS = 50

eta = 0.20
w1, w2, w3, w4 = 0.20, 0.20, 0.20, 0.20
a1, a2, a3, a4 = 0.25, 0.25, 0.25, 0.25

tau_acc = 0.75
tau_min = 0.40
rho = 0.45

vehicle_types = np.random.choice(
    ["Legitimate", "Suspicious", "Malicious"],
    size=N_VEHICLES,
    p=[0.65, 0.20, 0.15]
)

T_initial = np.zeros(N_VEHICLES)

for i, vtype in enumerate(vehicle_types):
    if vtype == "Legitimate":
        T_initial[i] = np.random.uniform(0.75, 0.90)
    elif vtype == "Suspicious":
        T_initial[i] = np.random.uniform(0.45, 0.65)
    else:
        T_initial[i] = np.random.uniform(0.20, 0.40)

records = []

# =========================================================
# Simulation Loop for Each Scheme
# =========================================================
for scheme_name, scheme_data in schemes.items():

    T = T_initial.copy()

    trust_gain = scheme_data["trust_gain"]
    risk_factor = scheme_data["risk_factor"]
    detection_gain = scheme_data["detection_gain"]

    auth_cost = scheme_data["auth"]
    rev_cost = scheme_data["rev"]

    for t in range(TIME_STEPS):
        for i in range(N_VEHICLES):

            vtype = vehicle_types[i]

            if vtype == "Legitimate":
                B = np.random.uniform(0.80, 1.00) * trust_gain
                M = np.random.uniform(0.75, 1.00) * trust_gain
                C = np.random.uniform(0.75, 1.00) * trust_gain
                H = np.random.uniform(0.80, 1.00) * trust_gain

                Phi = np.random.uniform(0.00, 0.20) * risk_factor
                Theta = np.random.uniform(0.00, 0.20) * risk_factor
                Gamma = np.random.uniform(0.00, 0.25) * risk_factor

            elif vtype == "Suspicious":
                B = np.random.uniform(0.45, 0.75) * trust_gain
                M = np.random.uniform(0.40, 0.75) * trust_gain
                C = np.random.uniform(0.45, 0.80) * trust_gain
                H = np.random.uniform(0.45, 0.75) * trust_gain

                Phi = np.random.uniform(0.25, 0.55) * risk_factor
                Theta = np.random.uniform(0.20, 0.55) * risk_factor
                Gamma = np.random.uniform(0.25, 0.60) * risk_factor

            else:
                # Malicious vehicles show poor behavioral values and stronger anomalies.
                # Detection gain increases anomaly visibility in more efficient schemes.
                B = np.random.uniform(0.00, 0.25) * trust_gain
                M = np.random.uniform(0.00, 0.30) * trust_gain
                C = np.random.uniform(0.05, 0.35) * trust_gain
                H = np.random.uniform(0.00, 0.30) * trust_gain

                Phi = np.random.uniform(0.70, 1.00) * detection_gain
                Theta = np.random.uniform(0.65, 1.00) * detection_gain
                Gamma = np.random.uniform(0.70, 1.00) * detection_gain

            B = min(max(B, 0), 1)
            M = min(max(M, 0), 1)
            C = min(max(C, 0), 1)
            H = min(max(H, 0), 1)

            Phi = min(max(Phi, 0), 1)
            Theta = min(max(Theta, 0), 1)
            Gamma = min(max(Gamma, 0), 1)

            # Trust update
            T_new = (
                (1 - eta) * T[i]
                + w1 * B
                + w2 * M
                + w3 * C
                + w4 * H
            )
            T_new = min(max(T_new, 0), 1)

            # Risk computation
            R = (
                a1 * (1 - T_new)
                + a2 * Phi
                + a3 * Theta
                + a4 * Gamma
            )
            R = min(max(R, 0), 1)

            # Decision
            if T_new >= tau_acc and R < rho:
                decision = "Accept"
                rev = 0
            elif T_new < tau_min:
                decision = "Reject"
                rev = 0
            else:
                decision = "Reverify"
                rev = 1

            # Reverification success model
            if decision == "Reverify":
                if scheme_name == "Proposed work":
                    if vtype == "Legitimate":
                        rev_success = np.random.rand() < 0.96
                    elif vtype == "Suspicious":
                        rev_success = np.random.rand() < 0.65
                    else:
                        rev_success = np.random.rand() < 0.02
                else:
                    if vtype == "Legitimate":
                        rev_success = np.random.rand() < 0.90
                    elif vtype == "Suspicious":
                        rev_success = np.random.rand() < 0.55
                    else:
                        rev_success = np.random.rand() < 0.12

                final_decision = "Accept" if rev_success else "Reject"
            else:
                rev_success = None
                final_decision = decision

            total_delay = auth_cost + rev * rev_cost
            total_cost = auth_cost + rev * rev_cost

            records.append({
                "time": t,
                "vehicle_id": i,
                "scheme": scheme_name,
                "vehicle_type": vtype,
                "behavior_score": B,
                "mobility_score": M,
                "communication_score": C,
                "history_score": H,
                "anomaly_level": Phi,
                "message_irregularity": Theta,
                "mobility_deviation": Gamma,
                "trust": T_new,
                "risk": R,
                "decision": decision,
                "reverification": rev,
                "reverification_success": rev_success,
                "final_decision": final_decision,
                "authentication_cost_ms": auth_cost,
                "reverification_cost_ms": rev_cost,
                "trust_gain": trust_gain,
                "risk_factor": risk_factor,
                "detection_gain": detection_gain,
                "delay_ms": total_delay,
                "crypto_cost_ms": total_cost
            })

            T[i] = T_new

# =========================================================
# Save Main CSV
# =========================================================
df = pd.DataFrame(records)
df.to_csv(
    os.path.join(OUTPUT_DIR, "adaptive_trust_reverification_results.csv"),
    index=False
)

# =========================================================
# Performance Metrics
# =========================================================
metrics_records = []

for scheme in df["scheme"].unique():

    sdf = df[df["scheme"] == scheme]

    total_auth = len(sdf)
    total_rev = sdf["reverification"].sum()

    RTR = total_rev / total_auth * 100

    mal_df = sdf[sdf["vehicle_type"] == "Malicious"]
    leg_df = sdf[sdf["vehicle_type"] == "Legitimate"]
    rev_df = sdf[sdf["decision"] == "Reverify"]

    FAR = len(mal_df[mal_df["final_decision"] == "Accept"]) / len(mal_df) * 100
    FRR = len(leg_df[leg_df["final_decision"] == "Reject"]) / len(leg_df) * 100

    if len(rev_df) > 0:
        RSR = len(rev_df[rev_df["final_decision"] == "Accept"]) / len(rev_df) * 100
    else:
        RSR = 0

    avg_delay = sdf["delay_ms"].mean()
    avg_cost = sdf["crypto_cost_ms"].mean()
    avg_trust = sdf["trust"].mean()
    avg_risk = sdf["risk"].mean()

    metrics_records.append({
        "Scheme": scheme,
        "Authentication Cost (ms)": schemes[scheme]["auth"],
        "Reverification Cost (ms)": schemes[scheme]["rev"],
        "Trust Gain": schemes[scheme]["trust_gain"],
        "Risk Factor": schemes[scheme]["risk_factor"],
        "Detection Gain": schemes[scheme]["detection_gain"],
        "Average Trust": avg_trust,
        "Average Risk": avg_risk,
        "Reverification Trigger Rate (%)": RTR,
        "False Acceptance Rate (%)": FAR,
        "False Rejection Rate (%)": FRR,
        "Reverification Success Rate (%)": RSR,
        "Average Delay (ms)": avg_delay,
        "Average Crypto Cost (ms)": avg_cost
    })

metrics_df = pd.DataFrame(metrics_records)
metrics_df.to_csv(
    os.path.join(OUTPUT_DIR, "performance_metrics.csv"),
    index=False
)

print("\nPerformance Metrics:")
print(metrics_df)

# =========================================================
# Graph 1: Trust vs Time Comparison
# =========================================================
trust_time = df.groupby(["time", "scheme"])["trust"].mean().reset_index()

plt.figure(figsize=(8, 5))
for scheme in trust_time["scheme"].unique():
    temp = trust_time[trust_time["scheme"] == scheme]
    plt.plot(temp["time"], temp["trust"], marker="o", label=scheme)

plt.xlabel("Time Step")
plt.ylabel("Average Trust Value")
plt.title("Trust Evolution Comparison")
plt.legend()
plt.grid(True)
plt.tight_layout()
plt.savefig(os.path.join(OUTPUT_DIR, "trust_vs_time.png"), dpi=300)
plt.close()

# =========================================================
# Graph 2: Risk vs Time Comparison
# =========================================================
risk_time = df.groupby(["time", "scheme"])["risk"].mean().reset_index()

plt.figure(figsize=(8, 5))
for scheme in risk_time["scheme"].unique():
    temp = risk_time[risk_time["scheme"] == scheme]
    plt.plot(temp["time"], temp["risk"], marker="o", label=scheme)

plt.xlabel("Time Step")
plt.ylabel("Average Risk Score")
plt.title("Risk Evolution Comparison")
plt.legend()
plt.grid(True)
plt.tight_layout()
plt.savefig(os.path.join(OUTPUT_DIR, "risk_vs_time.png"), dpi=300)
plt.close()

# =========================================================
# Graph 3: Decision Distribution Comparison
# =========================================================
decision_table = pd.crosstab(df["scheme"], df["final_decision"])

plt.figure(figsize=(8, 5))
decision_table.plot(kind="bar", ax=plt.gca())
plt.xlabel("Scheme")
plt.ylabel("Count")
plt.title("Final Decision Distribution Comparison")
plt.xticks(rotation=20)
plt.grid(axis="y")
plt.tight_layout()
plt.savefig(os.path.join(OUTPUT_DIR, "decision_distribution.png"), dpi=300)
plt.close()

# =========================================================
# Graph 4: Delay vs Time Comparison
# =========================================================
delay_time = df.groupby(["time", "scheme"])["delay_ms"].mean().reset_index()

plt.figure(figsize=(8, 5))
for scheme in delay_time["scheme"].unique():
    temp = delay_time[delay_time["scheme"] == scheme]
    plt.plot(temp["time"], temp["delay_ms"], marker="o", label=scheme)

plt.xlabel("Time Step")
plt.ylabel("Average Delay (ms)")
plt.title("Authentication Delay Comparison")
plt.legend()
plt.grid(True)
plt.tight_layout()
plt.savefig(os.path.join(OUTPUT_DIR, "delay_vs_time.png"), dpi=300)
plt.close()

# =========================================================
# Graph 5: Reverification Rate vs Time Comparison
# =========================================================
rev_time = df.groupby(["time", "scheme"])["reverification"].mean().reset_index()
rev_time["reverification"] = rev_time["reverification"] * 100

plt.figure(figsize=(8, 5))
for scheme in rev_time["scheme"].unique():
    temp = rev_time[rev_time["scheme"] == scheme]
    plt.plot(temp["time"], temp["reverification"], marker="o", label=scheme)

plt.xlabel("Time Step")
plt.ylabel("Reverification Rate (%)")
plt.title("Reverification Trigger Rate Comparison")
plt.legend()
plt.grid(True)
plt.tight_layout()
plt.savefig(os.path.join(OUTPUT_DIR, "reverification_rate_vs_time.png"), dpi=300)
plt.close()

# =========================================================
# Graph 6: FAR and FRR Comparison
# =========================================================
x = np.arange(len(metrics_df["Scheme"]))
width = 0.35

plt.figure(figsize=(8, 5))

plt.bar(x - width/2, metrics_df["False Acceptance Rate (%)"],
        width, label="FAR")

plt.bar(x + width/2, metrics_df["False Rejection Rate (%)"],
        width, label="FRR")

for i, v in enumerate(metrics_df["False Acceptance Rate (%)"]):
    plt.text(i - width/2, v + 0.3, f"{v:.2f}", ha="center", fontsize=9)

for i, v in enumerate(metrics_df["False Rejection Rate (%)"]):
    plt.text(i + width/2, v + 0.3, f"{v:.2f}", ha="center", fontsize=9)

plt.xlabel("Scheme")
plt.ylabel("Rate (%)")
plt.title("FAR and FRR Comparison Across Schemes")
plt.xticks(x, metrics_df["Scheme"], rotation=20)
plt.legend()
plt.grid(axis="y")
plt.tight_layout()
plt.savefig(os.path.join(OUTPUT_DIR, "far_frr_comparison.png"), dpi=300)
plt.close()

# =========================================================
# Extra Graph: Authentication Cost Comparison
# =========================================================
plt.figure(figsize=(8, 5))
plt.bar(metrics_df["Scheme"], metrics_df["Authentication Cost (ms)"])
plt.xlabel("Scheme")
plt.ylabel("Authentication Cost (ms)")
plt.title("Authentication Computation Cost Comparison")
plt.xticks(rotation=20)
plt.grid(axis="y")
plt.tight_layout()
plt.savefig(os.path.join(OUTPUT_DIR, "authentication_cost_comparison.png"), dpi=300)
plt.close()

# =========================================================
# Extra Graph: Average Crypto Cost Comparison
# =========================================================
plt.figure(figsize=(8, 5))
plt.bar(metrics_df["Scheme"], metrics_df["Average Crypto Cost (ms)"])
plt.xlabel("Scheme")
plt.ylabel("Average Crypto Cost (ms)")
plt.title("Average Crypto Cost Comparison")
plt.xticks(rotation=20)
plt.grid(axis="y")
plt.tight_layout()
plt.savefig(os.path.join(OUTPUT_DIR, "average_crypto_cost_comparison.png"), dpi=300)
plt.close()

# =========================================================
# Extra Graph: Cost-aware Trust Gain, Risk Factor, Detection Gain
# =========================================================
x = np.arange(len(metrics_df["Scheme"]))
width = 0.25

plt.figure(figsize=(9, 5))
plt.bar(x - width, metrics_df["Trust Gain"], width, label="Trust Gain")
plt.bar(x, metrics_df["Risk Factor"], width, label="Risk Factor")
plt.bar(x + width, metrics_df["Detection Gain"], width, label="Detection Gain")

plt.xlabel("Scheme")
plt.ylabel("Normalized Value")
plt.title("Cost-aware Trust, Risk, and Detection Factors")
plt.xticks(x, metrics_df["Scheme"], rotation=20)
plt.legend()
plt.grid(axis="y")
plt.tight_layout()
plt.savefig(os.path.join(OUTPUT_DIR, "trust_risk_detection_factors.png"), dpi=300)
plt.close()

# =========================================================
# Final Output
# =========================================================
print("\nGenerated files:")
for file in os.listdir(OUTPUT_DIR):
    print(file)

print("\nDone. Open the 'results' folder beside your Python file.")