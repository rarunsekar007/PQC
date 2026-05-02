import matplotlib.pyplot as plt
plt.rcParams['font.family'] = 'Times New Roman'
plt.rcParams['font.size'] = 12
plt.rcParams['axes.titlesize'] = 13
plt.rcParams['axes.labelsize'] = 12
plt.rcParams['xtick.labelsize'] = 11
plt.rcParams['ytick.labelsize'] = 11
plt.rcParams['legend.fontsize'] = 11
plt.rcParams['figure.titlesize'] = 14
# ============================================================
# CRYPTOGRAPHIC OPERATION COSTS in ms
# ============================================================
T_pm  = 0.3385
T_pa  = 0.0872
T_rnd = 0.0675
T_sm  = 0.0278
T_h   = 0.4758
T_cha = 0.3124
T_mod = 0.0427

# ============================================================
# SYSTEM PARAMETERS
# ============================================================
DATA_RATE_BPS = 6_000_000   # 6 Mbps
CPU_POWER_W = 10.88
TX_POWER_W = 10.88

# SUMO average values from your simulation
AVG_DENSITY = 40.0       # vehicles/km, change based on your CSV average
AVG_SPEED = 35.0         # km/h, change based on your CSV average
AVG_THROUGHPUT = 25.0    # vehicles/step, change based on your CSV average

# ============================================================
# EXISTING + PROPOSED SCHEMES
# ============================================================
SCHEMES = {
    "Liu et al.": {
        "comp_vehicle_ms": 6*T_pm + 5*T_pa + 5*T_h + T_cha + 2*T_mod,
        "comp_edge_ms":    6*T_pm + 5*T_pa + 5*T_h + T_cha + 2*T_mod,
        "comm_bytes": 6336,
    },
    "Yan et al.": {
        "comp_vehicle_ms": 2*T_pm + T_pa + 7*T_h,
        "comp_edge_ms":    8*T_pm + T_pa + 10*T_h,
        "comm_bytes": 4672,
    },
    "Ahmed et al.": {
        "comp_vehicle_ms": 12*T_pm + 2*T_pa + 3*T_h + T_cha + T_mod,
        "comp_edge_ms":    11*T_pm + 2*T_h + 6*T_mod,
        "comm_bytes": 4736,
    },
    "Proposed": {
        "comp_vehicle_ms": T_pm + T_rnd + T_h + T_sm + T_pa,
        "comp_edge_ms":    T_pm + T_rnd + 3*T_h + T_sm + 2*T_pa,
        "comm_bytes": 1968,
    },
}

# ============================================================
# FUNCTIONS
# ============================================================
def communication_delay_ms(comm_bytes):
    return (comm_bytes * 8 / DATA_RATE_BPS) * 1000.0

def total_computation_ms(v_ms, e_ms):
    return v_ms + e_ms

def total_delay_ms(v_ms, e_ms, comm_bytes):
    return total_computation_ms(v_ms, e_ms) + communication_delay_ms(comm_bytes)

def sumo_delay_ms(base_delay, density, speed):
    density_factor = 1 + density / 100.0
    speed_factor = 1 + speed / 100.0
    return base_delay * density_factor / speed_factor

def energy_comp_j(comp_ms):
    return (comp_ms / 1000.0) * CPU_POWER_W

def energy_comm_j(comm_bytes):
    return (comm_bytes * 8 * TX_POWER_W) / DATA_RATE_BPS

def effective_throughput(base_throughput, delay, min_delay):
    return base_throughput * (min_delay / delay)

# ============================================================
# CALCULATIONS
# ============================================================
labels = list(SCHEMES.keys())

energy_values = []
delay_values = []
sumo_delay_values = []
throughput_values = []

raw_delays = []

for scheme in labels:
    data = SCHEMES[scheme]
    delay = total_delay_ms(
        data["comp_vehicle_ms"],
        data["comp_edge_ms"],
        data["comm_bytes"]
    )
    raw_delays.append(delay)

min_delay = min(raw_delays)

for scheme in labels:
    data = SCHEMES[scheme]

    comp_total = total_computation_ms(
        data["comp_vehicle_ms"],
        data["comp_edge_ms"]
    )

    delay = total_delay_ms(
        data["comp_vehicle_ms"],
        data["comp_edge_ms"],
        data["comm_bytes"]
    )

    practical_delay = sumo_delay_ms(delay, AVG_DENSITY, AVG_SPEED)

    energy = energy_comp_j(comp_total) + energy_comm_j(data["comm_bytes"])

    throughput = effective_throughput(
        AVG_THROUGHPUT,
        delay,
        min_delay
    )

    energy_values.append(energy)
    delay_values.append(delay)
    sumo_delay_values.append(practical_delay)
    throughput_values.append(throughput)

# ============================================================
# PLOTTING SINGLE PDF WITH 4 SUBPLOTS
# ============================================================
COLORS = {
    "Liu et al.": "#1f77b4",     # blue
    "Yan et al.": "#ff7f0e",     # orange
    "Ahmed et al.": "#2ca02c",   # green
    "Proposed": "#d62728",       # red
}

bar_colors = [COLORS[label] for label in labels]
fig, axs = plt.subplots(2, 2, figsize=(12, 8))

# (a) Energy
bars = axs[0, 0].bar(labels, energy_values, color=bar_colors, edgecolor="black")
axs[0, 0].set_title("(a) Energy Consumption")
axs[0, 0].set_ylabel("Energy (J)")
axs[0, 0].tick_params(axis="x", rotation=20)
axs[0, 0].grid(axis="y", linestyle="--", alpha=0.5)

# (b) Delay
bars = axs[0, 1].bar(labels, delay_values, color=bar_colors, edgecolor="black")
axs[0, 1].set_title("(b) Authentication Delay")
axs[0, 1].set_ylabel("Delay (ms)")
axs[0, 1].tick_params(axis="x", rotation=20)
axs[0, 1].grid(axis="y", linestyle="--", alpha=0.5)

# (c) SUMO Delay
bars = axs[1, 0].bar(labels, sumo_delay_values, color=bar_colors, edgecolor="black")
axs[1, 0].set_title("(c) SUMO Practical Delay")
axs[1, 0].set_ylabel("SUMO Delay (ms)")
axs[1, 0].tick_params(axis="x", rotation=20)
axs[1, 0].grid(axis="y", linestyle="--", alpha=0.5)

# (d) Throughput
bars = axs[1, 1].bar(labels, throughput_values, color=bar_colors, edgecolor="black")
axs[1, 1].set_title("(d) Effective Throughput")
axs[1, 1].set_ylabel("Vehicles/step")
axs[1, 1].tick_params(axis="x", rotation=20)
axs[1, 1].grid(axis="y", linestyle="--", alpha=0.5)

# ============================================================
# ADD LEGEND (COMMON FOR ALL)
# ============================================================
handles = [plt.Rectangle((0,0),1,1,color=COLORS[l]) for l in labels]
fig.legend(handles, labels, loc="upper center", ncol=4, fontsize=10)

plt.tight_layout(rect=[0,0,1,0.95])

plt.savefig("colored_comparison.pdf", dpi=300)
plt.savefig("colored_comparison.png", dpi=300)

plt.show()

# ============================================================
# PRINT VALUES
# ============================================================
print("\nPerformance Comparison")
print("-" * 80)
print(f"{'Scheme':<15}{'Energy(J)':<15}{'Delay(ms)':<15}{'SUMO Delay(ms)':<18}{'Throughput':<15}")
print("-" * 80)

for i, scheme in enumerate(labels):
    print(
        f"{scheme:<15}"
        f"{energy_values[i]:<15.4f}"
        f"{delay_values[i]:<15.4f}"
        f"{sumo_delay_values[i]:<18.4f}"
        f"{throughput_values[i]:<15.4f}"
    )

print("\nPDF generated: proposed_vs_existing_energy_delay_throughput.pdf")