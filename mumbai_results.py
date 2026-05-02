import csv
from pathlib import Path
import matplotlib.pyplot as plt


INPUT_CSV = "proposed_work_log.csv"


def read_log(csv_path: Path):
    steps = []
    vehicles = []
    avg_speed = []
    accept = []
    reverify = []
    reject = []
    avg_trust = []
    avg_risk = []
    total_cost = []

    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)

        for row in reader:
            steps.append(int(row["step"]))
            vehicles.append(int(row["vehicles"]))
            avg_speed.append(float(row["avg_speed"]))
            accept.append(int(row["accept"]))
            reverify.append(int(row["reverify"]))
            reject.append(int(row["reject"]))
            total_cost.append(float(row["total_cost_ms"]))

            # If trust/risk columns are not present, avoid crash
            avg_trust.append(float(row.get("avg_trust", 0)))
            avg_risk.append(float(row.get("avg_risk", 0)))

    return steps, vehicles, avg_speed, accept, reverify, reject, avg_trust, avg_risk, total_cost


def safe_rate(numerator, denominator):
    if denominator == 0:
        return 0
    return (numerator / denominator) * 100


def plot_single(x, y, xlabel, ylabel, title, output_file):
    plt.figure(figsize=(8, 5))
    plt.plot(x, y, marker="o", linewidth=1.8, markersize=3)
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.title(title)
    plt.grid(True)
    plt.tight_layout()
    plt.savefig(output_file, dpi=300)
    plt.close()


def main():
    base_dir = Path.cwd()
    csv_path = base_dir / INPUT_CSV

    if not csv_path.exists():
        raise FileNotFoundError(
            f"{INPUT_CSV} not found in {base_dir}. Run your proposed-work main simulation first."
        )

    (
        steps,
        vehicles,
        avg_speed,
        accept,
        reverify,
        reject,
        avg_trust,
        avg_risk,
        total_cost,
    ) = read_log(csv_path)

    # Reverification rate per step
    rev_rate = [
        safe_rate(reverify[i], vehicles[i])
        for i in range(len(steps))
    ]

    # Reject rate per step
    reject_rate = [
        safe_rate(reject[i], vehicles[i])
        for i in range(len(steps))
    ]

    # Accept rate per step
    accept_rate = [
        safe_rate(accept[i], vehicles[i])
        for i in range(len(steps))
    ]

    # =====================================================
    # Individual IEEE Graphs
    # =====================================================
    plot_single(
        steps,
        avg_trust,
        xlabel="Simulation Step",
        ylabel="Average Trust Value",
        title="Trust Evolution Over Time",
        output_file=base_dir / "trust_vs_time.png",
    )

    plot_single(
        steps,
        avg_risk,
        xlabel="Simulation Step",
        ylabel="Average Risk Score",
        title="Risk Evolution Over Time",
        output_file=base_dir / "risk_vs_time.png",
    )

    plot_single(
        steps,
        rev_rate,
        xlabel="Simulation Step",
        ylabel="Reverification Rate (%)",
        title="Reverification Trigger Rate Over Time",
        output_file=base_dir / "reverification_rate_vs_time.png",
    )

    plot_single(
        steps,
        total_cost,
        xlabel="Simulation Step",
        ylabel="Cumulative Authentication Cost (ms)",
        title="Authentication Cost Over Time",
        output_file=base_dir / "auth_cost_vs_time.png",
    )

    plot_single(
        steps,
        accept_rate,
        xlabel="Simulation Step",
        ylabel="Accept Rate (%)",
        title="Accept Rate Over Time",
        output_file=base_dir / "accept_rate_vs_time.png",
    )

    plot_single(
        steps,
        reject_rate,
        xlabel="Simulation Step",
        ylabel="Reject Rate (%)",
        title="Reject Rate Over Time",
        output_file=base_dir / "reject_rate_vs_time.png",
    )

    # =====================================================
    # Combined 2x2 IEEE Figure
    # =====================================================
    fig, axes = plt.subplots(2, 2, figsize=(12, 9))

    # (a) Trust
    axes[0, 0].plot(steps, avg_trust, marker="o", linewidth=1.8, markersize=3)
    axes[0, 0].set_title("(a) Trust Evolution")
    axes[0, 0].set_xlabel("Simulation Step")
    axes[0, 0].set_ylabel("Average Trust Value")
    axes[0, 0].grid(True)

    # (b) Risk
    axes[0, 1].plot(steps, avg_risk, marker="o", linewidth=1.8, markersize=3)
    axes[0, 1].set_title("(b) Risk Evolution")
    axes[0, 1].set_xlabel("Simulation Step")
    axes[0, 1].set_ylabel("Average Risk Score")
    axes[0, 1].grid(True)

    # (c) Reverification
    axes[1, 0].plot(steps, rev_rate, marker="o", linewidth=1.8, markersize=3)
    axes[1, 0].set_title("(c) Reverification Trigger Rate")
    axes[1, 0].set_xlabel("Simulation Step")
    axes[1, 0].set_ylabel("Reverification Rate (%)")
    axes[1, 0].grid(True)

    # (d) Authentication Cost
    axes[1, 1].plot(steps, total_cost, marker="o", linewidth=1.8, markersize=3)
    axes[1, 1].set_title("(d) Authentication Cost")
    axes[1, 1].set_xlabel("Simulation Step")
    axes[1, 1].set_ylabel("Cumulative Cost (ms)")
    axes[1, 1].grid(True)

    plt.tight_layout()
    plt.savefig(base_dir / "adaptive_model_2x2.png", dpi=600)
    plt.savefig(base_dir / "adaptive_model_2x2.pdf", dpi=600)
    plt.close()

    print("Plots generated successfully:")
    print(" - trust_vs_time.png")
    print(" - risk_vs_time.png")
    print(" - reverification_rate_vs_time.png")
    print(" - auth_cost_vs_time.png")
    print(" - accept_rate_vs_time.png")
    print(" - reject_rate_vs_time.png")
    print(" - adaptive_model_2x2.png")
    print(" - adaptive_model_2x2.pdf")


if __name__ == "__main__":
    main()