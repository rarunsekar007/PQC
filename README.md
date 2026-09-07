ATPRV: REPRODUCIBILITY AND SUPPLEMENTARY IMPLEMENTATION
========================================================

Title:
ATPRV: Adaptive Trust-Based Lightweight Authentication with
Predictive Reverification for Post-Quantum VANETs


1. OVERVIEW
===========

This supplementary package provides the implementation and simulation
files used to support the reproducibility of the ATPRV framework.

The supplied programs cover four major components of the experimental
evaluation:

1. ATPRV trust and risk metric evaluation using SUMO/TraCI.
2. Threshold-sensitivity analysis for authentication and predictive
   reverification.
3. Markov transition estimation for predictive risk analysis.
4. Cryptographic primitive benchmarking for computation-cost analysis.

The programs are intended to reproduce the principal numerical and
simulation-based evaluations reported in the manuscript.


2. CONTENTS OF THE PACKAGE
==========================

FILE 1: ATPRV Trust/Risk Metric Implementation
-----------------------------------------------

Purpose:
Implements the four ATPRV trust metrics:

B_i(t) - Behavioral compliance
M_i(t) - Mobility consistency
C_i(t) - Communication reliability
H_i(t) - Historical authentication success

The program obtains vehicle position, speed, acceleration, and
simulation time from SUMO through TraCI.

Mobility consistency M_i(t) is calculated from the difference between
actual and predicted vehicle displacement.

Behavioral compliance B_i(t) considers factors including:

- timestamp freshness,
- replay/duplicate-message detection,
- message-rate compliance,
- speed plausibility,
- acceleration plausibility,
- mobility plausibility, and
- authentication outcome.

Communication reliability C_i(t) is evaluated using a lightweight
Python communication abstraction based on:

- vehicle-to-RSU distance,
- RSU communication range,
- vehicle density/congestion, and
- wireless packet-loss probability.

Historical authentication H_i(t) is calculated from previous
authentication and reverification outcomes.

The four metrics are subsequently used to update the ATPRV trust value
and determine the corresponding authentication decision.


FILE 2: ATPRV Threshold-Sensitivity Analysis
---------------------------------------------

Purpose:
Evaluates the influence of tau_min and tau_acc on ATPRV authentication
performance using a fixed SUMO mobility scenario.

The following threshold combinations are evaluated:

(tau_min, tau_acc)

(0.30, 0.60)
(0.30, 0.70)
(0.40, 0.60)
(0.40, 0.70)
(0.40, 0.80)
(0.50, 0.70)
(0.50, 0.80)

The principal performance metrics are:

FAR (%) =
Malicious vehicles finally accepted /
Total malicious authentication attempts x 100

FRR (%) =
Legitimate vehicles finally rejected /
Total legitimate authentication attempts x 100

RTR (%) =
Reverification decisions /
Total authentication attempts x 100

A fixed experiment seed is used so that the same vehicles, mobility
scenario, attack assignments, and communication conditions are retained
for every threshold combination.

The threshold pair is therefore the principal decision parameter varied
during the sensitivity analysis.


FILE 3: ATPRV Markov Transition Estimation
------------------------------------------

Purpose:
Estimates the state-transition probabilities used by the predictive
component of ATPRV.

The trust/risk observations are mapped into discrete states such as:

L - Low
M - Medium
H - High

The transition probability from state a to state b is estimated as:

P_ab = N_ab / Sum_c(N_ac)

where N_ab represents the number of observed transitions from state a
to state b.

The resulting transition matrix provides an empirical representation
of changes in vehicle state over successive observation intervals and
supports predictive reverification decisions.

The Markov estimation is based on observed state transitions rather
than manually assigning transition probabilities.


FILE 4: ATPRV Cryptographic Operation Benchmark
------------------------------------------------

Purpose:
Measures the execution times of the cryptographic and arithmetic
operations used in the ATPRV computation-cost analysis.

The benchmark includes the primitive operations required by ATPRV and
the compared authentication schemes, including:

- polynomial multiplication,
- polynomial addition,
- LWR rounding,
- scalar multiplication,
- polynomial sampling,
- reconciliation/Cha operation,
- modular arithmetic,
- cryptographic hashing,
- symmetric cryptography,
- fuzzy-extractor-related operation, where applicable, and
- XOR operation.

All primitive timings used in the comparative computational analysis
are evaluated under a common benchmarking environment wherever the
operations are equivalent.

Each primitive is executed after 100 warm-up iterations and is then
measured over 2000 repetitions. The mean execution time is used for
the computational comparison.


3. HARDWARE CONFIGURATION
=========================

The cryptographic operation benchmark was executed using:

Operating System : Windows 11, 64-bit
Processor        : AMD Ryzen 7 5800U with Radeon Graphics
Clock frequency  : 1.90 GHz
System memory    : 16 GB RAM
GPU acceleration : Not used


4. SOFTWARE CONFIGURATION
=========================

Python version        : Python 3.13.7
Mobility simulator    : SUMO
SUMO interface        : TraCI
Polynomial operations : NumPy
Hash operations       : Python hashlib
Symmetric crypto      : cryptography/OpenSSL backend

The SUMO_HOME environment variable must be configured before executing
the SUMO/TraCI programs.


5. LATTICE IMPLEMENTATION PARAMETERS
====================================

The ATPRV lattice implementation employs the polynomial ring:

R_q = Z_q[x]/(x^n + 1)

with the principal implementation parameters:

n = 1024
q = 12289

The LWR-based authentication operations are evaluated using the same
parameter configuration throughout the ATPRV computational benchmark.

Security claims should be interpreted according to the LWR hardness
assumption and the parameter set specified in the accompanying
manuscript.


6. ATPRV TRUST AND RISK PARAMETERS
==================================

Trust decay parameter:

eta = 0.20

Trust weights:

omega_B = 0.05
omega_M = 0.05
omega_C = 0.05
omega_H = 0.05

The normalization condition is:

(1 - eta) + omega_B + omega_M + omega_C + omega_H = 1.

Initial trust:

T_i(0) = 0.50

Risk coefficients:

alpha_1 = 0.25
alpha_2 = 0.25
alpha_3 = 0.25
alpha_4 = 0.25

Therefore:

alpha_1 + alpha_2 + alpha_3 + alpha_4 = 1.

Risk threshold:

rho = 0.50


7. SUMO SIMULATION CONFIGURATION
================================

Mobility scenario        : Mumbai road network
SUMO step length         : 1.0 s
Maximum simulation steps : 1000
RSU communication range  : 300 m
Experiment seed          : 2026
Malicious vehicle ratio  : 20%
Base packet success      : 0.99

The corresponding SUMO network and route files should be placed in the
same working directory as the simulation program when required.


8. CONTROLLED ATTACK CONFIGURATION
==================================

For threshold-sensitivity evaluation, malicious vehicles are assigned
controlled attack profiles including:

- replay,
- message irregularity,
- mobility deviation, and
- stealth behavior.

The ground-truth vehicle labels and attack classes are generated
reproducibly using the fixed experiment seed.

The controlled attack model is used to investigate how the ATPRV
trust-risk decision mechanism responds to different anomalous vehicle
behaviors.

The attack-related probabilities used by the program are simulation
parameters and should not be interpreted as measured real-world attack
probabilities.


9. REPRODUCIBILITY CONDITIONS
=============================

To ensure a consistent comparison:

1. A fixed experiment seed is used.
2. The same SUMO road network and vehicle routes are retained.
3. The same vehicle ground-truth labels are used across threshold runs.
4. The same attack assignments are retained across threshold runs.
5. Trust and risk weights remain fixed.
6. Only the specified threshold pair is varied during threshold
   sensitivity evaluation.
7. Equivalent cryptographic primitives are benchmarked under the same
   hardware/software environment.
8. Cryptographic benchmark operations use 100 warm-up iterations and
   2000 measured repetitions.
9. Mean execution time is used when calculating computational overhead.


10. OUTPUT FILES
================

Depending on the program executed, the supplementary implementation
generates CSV files containing:

- ATPRV trust/risk metrics,
- vehicle-level simulation observations,
- threshold-sensitivity results,
- FAR, FRR, and RTR values,
- authentication/reverification decisions,
- event-level simulation information, and
- Markov state-transition information.

For the threshold-sensitivity experiment, the principal outputs are:

ATPRV_threshold_sensitivity_results.csv

and

ATPRV_threshold_event_log.csv


11. HOW TO RUN THE SUMO PROGRAMS
================================

1. Install Python and SUMO.

2. Configure the SUMO_HOME environment variable.

3. Ensure that the SUMO TraCI Python package is accessible.

4. Place the required SUMO network/route files and the corresponding
   Python program in the working directory.

5. Open the program using Visual Studio Code or a Python terminal.

6. Execute the required Python program.

For the threshold-sensitivity program, normal execution does not require
additional command-line arguments when the SUMO files are available in
the expected directory.


12. HOW TO RUN THE CRYPTOGRAPHIC BENCHMARK
==========================================

1. Install Python 3.13.7 or a compatible Python 3 environment.

2. Install the required Python packages, including NumPy and
   cryptography.

3. Execute the cryptographic benchmark Python program.

4. Allow the complete warm-up and measurement iterations to finish.

5. The mean execution times reported by the program can be used with
   the operation counts reported in the manuscript to reproduce the
   computational-cost comparison.


13. METHODOLOGICAL SCOPE
========================

SUMO/TraCI directly provides the vehicular mobility information,
including position, speed, acceleration, and simulation time.

Because a separate packet-level network simulator is not employed,
communication reliability is represented through a reproducible
Python-level abstraction based on distance, vehicle density,
communication range, and wireless-loss parameters.

Therefore, the SUMO experiments should be interpreted as protocol-level
ATPRV evaluations over realistic vehicular mobility traces and not as
full wireless PHY/MAC simulations.

Similarly, controlled attack injection in the threshold-sensitivity
program is intended to evaluate the response of the ATPRV trust and
risk mechanism under reproducible anomalous conditions. It does not
represent a complete cyber-physical implementation of each attack.


14. FAIR PERFORMANCE COMPARISON
===============================

For computational comparison, the operation counts of ATPRV and the
compared schemes are derived from their respective protocol procedures.
Where equivalent primitive operations are required, their execution
costs are evaluated using the common benchmark environment described
above.

This approach avoids directly comparing execution times obtained from
different processors, programming languages, operating systems, or
experimental platforms.

Differences in cryptographic construction and lattice parameters among
the compared schemes should therefore be considered together with the
reported operation counts and security assumptions.


15. NOTE FOR REPRODUCIBILITY
============================

The supplied source files are supplementary research implementations
intended to reproduce the numerical and simulation-based evaluations
reported for ATPRV. Parameter values are explicitly defined in the
corresponding source files so that individual experiments can be
inspected and repeated.

Any modification of the SUMO scenario, random seed, communication
parameters, attack configuration, trust/risk weights, lattice
parameters, or threshold values may produce results different from
those reported in the manuscript.
