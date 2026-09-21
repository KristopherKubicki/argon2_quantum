"""Run bounded, reproducible synthetic attack comparisons with honest labels."""

from dataclasses import asdict
import hashlib
import hmac
import json
import math

from .model import (
    Context,
    DLogOracle,
    G,
    P,
    Q,
    World,
    confirmation_oracle_attack,
    digest,
    frame,
    known_wrapping_key_attack,
    reusable_static_B_attack,
    stolen_credentials_attack,
    transcript_attack,
)


SOURCES = [
    {
        "title": "QA-KHAPE, Figure 1 and limitations",
        "url": "https://eprint.iacr.org/2023/1513",
    },
    {
        "title": "Quantum generic groups, Theorem 4.5",
        "url": "https://arxiv.org/abs/2307.03065",
    },
    {
        "title": "Original quantum-annoying model",
        "url": "https://eprint.iacr.org/2021/696",
    },
]


def batch_work_proxy(guesses: int, batch_size: int, group_bits: int = 256) -> float:
    """Illustrate an asymptotic upper-bound shape, NOT timing or a lower bound.

    Normalize a single solve to one arbitrary unit. For full batches large enough
    to enter m >= log2(|G|), use m/log2(m). Other terms/constants and quantum memory
    are omitted. Small tails use independent solves. Finite ratios are scenarios,
    not predictions from the theorem. This function never measures toy BSGS cost.
    """
    if (
        type(guesses) is not int
        or not 1 <= guesses <= 1_000_000_000
        or type(batch_size) is not int
        or not 1 <= batch_size <= 1_000_000
        or type(group_bits) is not int
        or not 128 <= group_bits <= 1024
    ):
        raise ValueError("invalid scenario parameters")
    if batch_size < group_bits:
        return float(guesses)
    full, tail = divmod(guesses, batch_size)
    tail_work = tail if tail < group_bits else tail / math.log2(tail)
    return full * batch_size / math.log2(batch_size) + tail_work


def run_experiment(guesses: int = 32, seed: int = 20260921) -> dict:
    if type(guesses) is not int or not 2 <= guesses <= 128:
        raise ValueError("guesses must be an integer from 2 to 128")
    if type(seed) is not int or not 0 <= seed < 2**32:
        raise ValueError("seed must be a 32-bit unsigned integer")
    dictionary = [f"synthetic-password-{i:03d}" for i in range(guesses)]
    password = dictionary[-1]
    cases = []
    for hidden, name in ((False, "public-X control"), (True, "hidden-X transcript")):
        world = World(seed)
        credentials = world.register(password)
        transcript = world.exchange(
            credentials, password, Context("session-1"), hidden_X=hidden
        )
        if transcript is None:
            raise RuntimeError("honest handshake failed")
        result = transcript_attack(world, transcript, dictionary, DLogOracle())
        cases.append({"name": name, **asdict(result)})
    # Continue the hidden-X world. Attacks only receive explicitly specified data.
    cases.append(
        {
            "name": "wrapping-key disclosure",
            **asdict(
                known_wrapping_key_attack(
                    world,
                    transcript,
                    credentials.wrapping_key,
                    dictionary,
                    DLogOracle(),
                )
            ),
        }
    )
    cases.append(
        {
            "name": "stolen server credentials",
            **asdict(stolen_credentials_attack(world, credentials, dictionary)),
        }
    )
    tag = hmac.digest(
        digest("bad-envelope-key", password),
        frame("envelope", credentials.envelope),
        "sha256",
    )
    cases.append(
        {
            "name": "password-confirming envelope control",
            **asdict(confirmation_oracle_attack(credentials.envelope, tag, dictionary)),
        }
    )
    second = world.exchange(credentials, password, Context("session-2"))
    if second is None:
        raise RuntimeError("second honest handshake failed")
    shared_oracle = DLogOracle()
    first_attack = reusable_static_B_attack(
        world, transcript, dictionary, shared_oracle
    )
    second_attack = reusable_static_B_attack(world, second, dictionary, shared_oracle)
    if (
        any(case["recovered"] != password for case in cases)
        or first_attack.recovered != password
        or second_attack.recovered != password
    ):
        raise RuntimeError("demonstration attack failed to recover synthetic password")
    return {
        "schema": "quantum-annoying-lab/v1",
        "seed": seed,
        "status": "INSECURE RESEARCH SIMULATOR — NOT FOR PASSWORDS OR DEPLOYMENT",
        "group": {"p": P, "q": Q, "g": G, "order_bits": Q.bit_length()},
        "dictionary_size": guesses,
        "correct_guess_rank": guesses,
        "honest_handshake": {"mutual_confirmation": True, "quantum_calls": 0},
        "model": {
            "cipher": (
                "lazy ideal-cipher tables; not an implementable distributed cipher"
            ),
            "oracle": "classical baby-step giant-step with cached answers",
            "randomness": "public deterministic seed; all data synthetic",
            "scope": (
                "specific attack demonstrations, not optimality or security proofs"
            ),
        },
        "cases": cases,
        "cross_session": {
            "name": "reuse candidate static-B logs across two sessions",
            "sessions": 2,
            "dictionary_guesses_total": first_attack.guesses + second_attack.guesses,
            "first_session": first_attack.metrics,
            "cumulative": second_attack.metrics,
            "distinct_targets_added_second_session": (
                second_attack.metrics["distinct_dlog_targets"]
                - first_attack.metrics["distinct_dlog_targets"]
            ),
            "interpretation": (
                "previous candidate-B solutions are reused; each new Y adds one target"
            ),
        },
        "batch_scenario": {
            "status": "ILLUSTRATIVE ASYMPTOTIC SHAPE ONLY, NO QUANTUM BENCHMARK",
            "assumed_group_bits": 256,
            "hypothetical_guesses": 65536,
            "independent_units": 65536,
            "batch_256_proxy_units": batch_work_proxy(65536, 256),
            "batch_4096_proxy_units": batch_work_proxy(65536, 4096),
            "omissions": [
                "hidden constants",
                "quantum memory",
                "circuit compilation",
                "error correction",
                "hardware time",
                "non-generic attacks",
            ],
        },
        "sources": SOURCES,
    }


def canonical_report(report: dict) -> str:
    return json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def report_digest(report: dict) -> str:
    return hashlib.sha256(canonical_report(report).encode()).hexdigest()
