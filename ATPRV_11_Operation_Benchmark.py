#!/usr/bin/env python3

"""
ATPRV Primitive Benchmark

Polynomial Ring:
    R_q = Z_q[x] / (x^n + 1)

Parameters:
    n = 1024
    q = 12289
    p = 256
"""

import os
import sys
import time
import hashlib
import hmac
import statistics
import platform
from dataclasses import dataclass

import numpy as np


# ============================================================
# ATPRV Lattice Parameters
# ============================================================

N = 1024
Q = 12289
P = 256
BETA = 3.2

WARMUP = 100
REPETITIONS = 2000

AES_MSG_BYTES = 1024
HASH_MSG_BYTES = 1024
XOR_BYTES = 1024


# ============================================================
# AES-GCM / OpenSSL Backend
# ============================================================

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    CRYPTOGRAPHY_AVAILABLE = True
except Exception:
    CRYPTOGRAPHY_AVAILABLE = False


# ============================================================
# Optional SageMath / NTL Backend
# ============================================================

try:
    from sageall import PolynomialRing, Integers
    SAGE_NTL_AVAILABLE = True

except Exception:

    try:
        from sage.all import PolynomialRing, Integers
        SAGE_NTL_AVAILABLE = True

    except Exception:
        SAGE_NTL_AVAILABLE = False


# ============================================================
# Result Structure
# ============================================================

@dataclass
class Result:
    name: str
    symbol: str
    mean_ms: float
    median_ms: float
    stdev_ms: float
    min_ms: float
    max_ms: float


# ============================================================
# Benchmark Function
# ============================================================

def benchmark(fn, warmup=WARMUP, repetitions=REPETITIONS):

    # Warm-up executions
    for _ in range(warmup):
        fn()

    timings = []

    for _ in range(repetitions):

        start = time.perf_counter_ns()

        fn()

        end = time.perf_counter_ns()

        timings.append((end - start) / 1e6)

    return (
        statistics.mean(timings),
        statistics.median(timings),
        statistics.stdev(timings),
        min(timings),
        max(timings),
    )


# ============================================================
# Random Generator
# ============================================================

rng = np.random.default_rng(123456789)


def random_poly_numpy(modulus=Q):

    return rng.integers(
        0,
        modulus,
        size=N,
        dtype=np.int64
    )


# ============================================================
# Negacyclic Polynomial Multiplication
#
# R_q = Z_q[x] / (x^1024 + 1)
# ============================================================

def negacyclic_mul_numpy(a, b, modulus=Q):

    conv = np.convolve(a, b)

    low = conv[:N].astype(object)

    high = conv[N:]

    # Because x^N = -1 in R_q
    for k, value in enumerate(high):
        low[k] -= int(value)

    return np.array(
        [int(value) % modulus for value in low],
        dtype=np.int64
    )


# ============================================================
# Lattice Backend Selection
# ============================================================

if SAGE_NTL_AVAILABLE:

    Zq = Integers(Q)

    R = PolynomialRing(Zq, "x")

    x = R.gen()

    MOD_POLY = x**N + 1


    def sage_poly_from_numpy(poly):

        return R([int(v) for v in poly])


    def poly_mul(a, b):

        A = sage_poly_from_numpy(a)

        B = sage_poly_from_numpy(b)

        return (A * B) % MOD_POLY


    LATTICE_BACKEND = (
        "SageMath/NTL-backed polynomial arithmetic"
    )

else:

    def poly_mul(a, b):

        return negacyclic_mul_numpy(
            a,
            b,
            Q
        )


    LATTICE_BACKEND = (
        "NumPy reference fallback (NOT NTL)"
    )


# ============================================================
# Pre-generated Polynomial Inputs
# ============================================================

a = random_poly_numpy(Q)

b = random_poly_numpy(Q)

round_input = random_poly_numpy(Q)

scalar = 7

mod_input = rng.integers(
    -(Q * Q),
    Q * Q,
    size=N,
    dtype=np.int64
)


# ============================================================
# 1. Polynomial Multiplication
# ============================================================

def op_poly_mul():

    poly_mul(a, b)


# ============================================================
# 2. Polynomial Addition
# ============================================================

def op_poly_add():

    _ = (a + b) % Q


# ============================================================
# 3. LWR Rounding
#
# Round_{q -> p}(z)
# ============================================================

def op_lwr_round():

    _ = (
        np.rint(
            (P / Q) * round_input
        )
        .astype(np.int64)
        % P
    )


# ============================================================
# 4. Scalar Multiplication
# ============================================================

def op_scalar_mul():

    _ = (scalar * a) % Q


# ============================================================
# 5. Share Polynomial Generation
# ============================================================

def op_share_poly_generation():

    _ = np.clip(
        np.rint(
            rng.normal(
                0.0,
                BETA,
                size=N
            )
        ),
        -8,
        8
    ).astype(np.int64) % Q


# ============================================================
# 6. Cha Function
# ============================================================

def cha_function(data):

    digest = hashlib.sha256(data).digest()

    return (
        int.from_bytes(
            digest,
            "big"
        )
        % Q
    )


cha_msg = os.urandom(
    HASH_MSG_BYTES
)


def op_cha():

    cha_function(
        cha_msg
    )


# ============================================================
# 7. Modulo Operation
# ============================================================

def op_mod():

    _ = mod_input % Q


# ============================================================
# 8. Hash Computation
# ============================================================

hash_msg = os.urandom(
    HASH_MSG_BYTES
)


def op_hash():

    hashlib.sha256(
        hash_msg
    ).digest()


# ============================================================
# 9. AES-GCM Encryption / Decryption
# ============================================================

if CRYPTOGRAPHY_AVAILABLE:

    aes_key = AESGCM.generate_key(
        bit_length=256
    )

    aesgcm = AESGCM(
        aes_key
    )

    aes_nonce = os.urandom(12)

    aes_plaintext = os.urandom(
        AES_MSG_BYTES
    )

    aes_aad = b"ATPRV-benchmark"


    def op_aes_gcm_enc_dec():

        ciphertext = aesgcm.encrypt(
            aes_nonce,
            aes_plaintext,
            aes_aad
        )

        aesgcm.decrypt(
            aes_nonce,
            ciphertext,
            aes_aad
        )


else:

    def op_aes_gcm_enc_dec():

        raise RuntimeError(
            "cryptography package not installed. "
            "Install using: pip install cryptography"
        )


# ============================================================
# 10. Fuzzy Extractor
# ============================================================

fe_source = os.urandom(64)


def fe_gen(source):

    key = hashlib.sha256(
        source
    ).digest()

    helper = hmac.new(
        key,
        b"ATPRV-FE-helper",
        hashlib.sha256
    ).digest()

    return key, helper


def fe_rep(source, helper):

    key = hashlib.sha256(
        source
    ).digest()

    expected = hmac.new(
        key,
        b"ATPRV-FE-helper",
        hashlib.sha256
    ).digest()

    if not hmac.compare_digest(
        helper,
        expected
    ):
        raise ValueError(
            "Fuzzy extractor reconstruction failed"
        )

    return key


def op_fuzzy_extractor():

    key, helper = fe_gen(
        fe_source
    )

    fe_rep(
        fe_source,
        helper
    )


# ============================================================
# 11. XOR Operation
# ============================================================

xor_a = os.urandom(
    XOR_BYTES
)

xor_b = os.urandom(
    XOR_BYTES
)


def op_xor():

    _ = bytes(
        x ^ y
        for x, y in zip(
            xor_a,
            xor_b
        )
    )


# ============================================================
# Main Benchmark
# ============================================================

def main():

    print("=" * 78)

    print(
        "ATPRV Primitive Benchmark"
    )

    print("=" * 78)

    print(
        f"Python          : "
        f"{sys.version.split()[0]}"
    )

    print(
        f"Platform        : "
        f"{platform.platform()}"
    )

    print(
        f"Processor       : "
        f"{platform.processor() or 'Not reported'}"
    )

    print(
        f"Polynomial ring : "
        f"Z_{Q}[x]/(x^{N} + 1)"
    )

    print(
        f"n               : {N}"
    )

    print(
        f"q               : {Q}"
    )

    print(
        f"p               : {P}"
    )

    print(
        f"Warm-up runs    : {WARMUP}"
    )

    print(
        f"Measured runs   : {REPETITIONS}"
    )

    print(
        f"Lattice backend : "
        f"{LATTICE_BACKEND}"
    )

    print(
        "AES-GCM backend : "
        + (
            "cryptography/OpenSSL"
            if CRYPTOGRAPHY_AVAILABLE
            else "UNAVAILABLE"
        )
    )

    print("=" * 78)


    operations = [

        (
            "Polynomial Multiplication",
            "T_pm",
            op_poly_mul
        ),

        (
            "Polynomial Addition",
            "T_pa",
            op_poly_add
        ),

        (
            "LWR Rounding",
            "T_rnd",
            op_lwr_round
        ),

        (
            "Scalar Multiplication",
            "T_sm",
            op_scalar_mul
        ),

        (
            "Share Polynomial Generation",
            "T_spl",
            op_share_poly_generation
        ),

        (
            "Cha Function",
            "T_cha",
            op_cha
        ),

        (
            "Modulo Operation",
            "T_mod",
            op_mod
        ),

        (
            "Hash Computation",
            "T_h",
            op_hash
        ),

        (
            "AES-GCM Enc/Dec",
            "T_sym",
            op_aes_gcm_enc_dec
        ),

        (
            "Fuzzy Extractor",
            "T_fe",
            op_fuzzy_extractor
        ),

        (
            "XOR Operation",
            "T_xor",
            op_xor
        )
    ]


    results = []


    for name, symbol, function in operations:

        try:

            mean_, median_, sd_, min_, max_ = benchmark(
                function
            )

            result = Result(
                name,
                symbol,
                mean_,
                median_,
                sd_,
                min_,
                max_
            )

            results.append(
                result
            )

            print(
                f"{name:30s} "
                f"{mean_:10.6f} ms"
            )

        except Exception as error:

            print(
                f"{name:30s} "
                f"ERROR: {error}"
            )


    # ========================================================
    # Detailed Results
    # ========================================================

    print("\n")

    print(
        f"{'S.No':<5} "
        f"{'Description':<30} "
        f"{'Symbol':<8} "
        f"{'Mean(ms)':>12} "
        f"{'Median':>12} "
        f"{'Std.Dev':>12} "
        f"{'Min':>12} "
        f"{'Max':>12}"
    )

    print("-" * 108)


    for i, result in enumerate(
        results,
        start=1
    ):

        print(
            f"{i:<5} "
            f"{result.name:<30} "
            f"{result.symbol:<8} "
            f"{result.mean_ms:12.6f} "
            f"{result.median_ms:12.6f} "
            f"{result.stdev_ms:12.6f} "
            f"{result.min_ms:12.6f} "
            f"{result.max_ms:12.6f}"
        )


    # ========================================================
    # Save CSV
    # ========================================================

    csv_name = (
        "atprv_operation_benchmark_n1024.csv"
    )


    with open(
        csv_name,
        "w",
        encoding="utf-8"
    ) as file:

        file.write(
            "S.No,Description,Symbol,"
            "Mean_ms,Median_ms,"
            "StdDev_ms,Min_ms,Max_ms\n"
        )


        for i, result in enumerate(
            results,
            start=1
        ):

            file.write(

                f'{i},'
                f'"{result.name}",'
                f'{result.symbol},'
                f'{result.mean_ms:.9f},'
                f'{result.median_ms:.9f},'
                f'{result.stdev_ms:.9f},'
                f'{result.min_ms:.9f},'
                f'{result.max_ms:.9f}\n'
            )


    print(
        "\nResults saved to: "
        f"{csv_name}"
    )


if __name__ == "__main__":
    main()