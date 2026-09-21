"""Properties and attacks for the source-only, insecure QA lab."""

from dataclasses import replace
import json
from pathlib import Path
import random
import subprocess

import pytest

from research.quantum_annoying.experiment import (
    batch_work_proxy,
    canonical_report,
    report_digest,
    run_experiment,
)
from research.quantum_annoying.model import (
    Context,
    DLogOracle,
    G,
    IdealCipher,
    P,
    Q,
    World,
    known_wrapping_key_attack,
    point,
    reusable_static_B_attack,
    stolen_credentials_attack,
    transcript_attack,
)
from research.quantum_annoying.report import render_html


@pytest.mark.parametrize("seed", range(8))
def test_honest_mutual_key_agreement_and_wrong_password(seed):
    world = World(seed)
    registration = world.register("synthetic-correct")
    context = Context("test-session")
    y, challenge = world.begin(registration)
    key, flight = world.respond(context, "synthetic-correct", challenge)
    accepted = world.accept(context, registration, y, challenge, flight)
    assert accepted is not None
    confirmation, server_key = accepted
    assert world.finish(key, confirmation) == server_key
    assert world.finish(key, b"incorrect") is None
    assert world.exchange(registration, "synthetic-wrong", Context("another")) is None


@pytest.mark.parametrize("hidden", [False, True])
def test_correctness_does_not_depend_on_attack_mode(hidden):
    world = World(7)
    registration = world.register("synthetic")
    assert world.exchange(registration, "synthetic", Context("s"), hidden_X=hidden)


def test_replay_and_identity_substitution_fail():
    world = World(42)
    registration = world.register("synthetic")
    context = Context("original-session")
    y, challenge = world.begin(registration)
    _, flight = world.respond(context, "synthetic", challenge)
    for changed in (
        replace(context, sid="different-session"),
        replace(context, client="another-client"),
        replace(context, server="another-server"),
    ):
        assert world.accept(changed, registration, y, challenge, flight) is None
    new_y, new_challenge = world.begin(registration)
    assert world.accept(context, registration, new_y, new_challenge, flight) is None


def test_tampering_fails_confirmation():
    world = World(99)
    registration = world.register("synthetic")
    context = Context("s")
    y, challenge = world.begin(registration)
    _, flight = world.respond(context, "synthetic", challenge)
    for altered in (
        replace(flight, confirmation=b"0" * 32),
        replace(flight, transmitted_X=(flight.transmitted_X + 1) % Q),
    ):
        assert world.accept(context, registration, y, challenge, altered) is None


def test_ideal_cipher_bijection_and_wrong_key_plausibility():
    rng = random.Random(1234)
    cipher = IdealCipher(rng, 16, lambda: rng.randrange(16))
    ciphertexts = [cipher.encrypt(b"key", i) for i in range(16)]
    assert len(set(ciphertexts)) == 16
    assert [cipher.decrypt(b"key", c) for c in ciphertexts] == list(range(16))
    for c in ciphertexts:
        wrong = cipher.decrypt(b"wrong-key", c)
        assert 0 <= wrong < 16
        assert cipher.encrypt(b"wrong-key", wrong) == c
    with pytest.raises(ValueError):
        cipher.decrypt(b"key", 16)
    with pytest.raises(ValueError):
        cipher.decrypt(b"key", True)
    with pytest.raises(TypeError):
        cipher.encrypt("not bytes", 1)


def test_envelope_wrong_keys_have_no_decoding_oracle():
    world = World(71)
    registration = world.register("synthetic-correct")
    for i in range(50):
        a, B, sk = world.candidate(f"wrong-{i}", registration.envelope)
        assert 0 <= a < Q
        assert point(B) == B
        assert 0 <= sk < 2**128


def test_discrete_log_solver_and_shared_cache():
    oracle = DLogOracle()
    for exponent in (0, 1, 2, 100, Q - 1):
        target = pow(G, exponent, P)
        assert oracle.solve(target) == exponent
        assert oracle.solve(target) == exponent
    assert oracle.requests == 10
    assert oracle.unique_targets == 5
    with pytest.raises(ValueError):
        oracle.solve(0)
    with pytest.raises(ValueError):
        oracle.solve(P - 1)


@pytest.mark.parametrize("seed", [3, 19, 20260921])
def test_attack_counts_and_failure_boundaries(seed):
    report = run_experiment(16, seed)
    cases = {case["name"]: case for case in report["cases"]}
    assert cases["public-X control"]["metrics"]["distinct_dlog_targets"] == 1
    assert cases["hidden-X transcript"]["metrics"]["distinct_dlog_targets"] == 16
    assert cases["wrapping-key disclosure"]["metrics"]["distinct_dlog_targets"] == 1
    assert cases["stolen server credentials"]["metrics"]["dlog_requests"] == 0
    assert (
        cases["password-confirming envelope control"]["metrics"]["dlog_requests"] == 0
    )
    assert report["cross_session"]["cumulative"]["distinct_dlog_targets"] == 18
    assert report["cross_session"]["distinct_targets_added_second_session"] == 1
    assert all(case["guesses"] == 16 for case in cases.values())


def test_missing_password_does_not_produce_false_recovery():
    world = World(5)
    registration = world.register("synthetic-real")
    transcript = world.exchange(registration, "synthetic-real", Context("s"))
    dictionary = ["synthetic-other", "synthetic-wrong"]
    assert (
        transcript_attack(world, transcript, dictionary, DLogOracle()).recovered is None
    )
    assert stolen_credentials_attack(world, registration, dictionary).recovered is None
    result = known_wrapping_key_attack(
        world, transcript, registration.wrapping_key, dictionary, DLogOracle()
    )
    assert result.recovered is None
    result = reusable_static_B_attack(world, transcript, dictionary, DLogOracle())
    assert result.recovered is None


def test_duplicate_guesses_are_not_distinct_work():
    world = World(92)
    registration = world.register("right")
    transcript = world.exchange(registration, "right", Context("s"))
    result = transcript_attack(
        world, transcript, ["wrong", "wrong", "right"], DLogOracle()
    )
    assert result.guesses == 3
    assert result.metrics["dlog_requests"] == 3
    assert result.metrics["distinct_dlog_targets"] == 2


def test_reproduction_matches_committed_evidence():
    evidence = Path("research/results/experiment.json").read_text(encoding="utf-8")
    report = run_experiment()
    assert canonical_report(report) == evidence
    assert len(report_digest(report)) == 64
    assert render_html(report) == Path("research/results/index.html").read_text(
        encoding="utf-8"
    )


@pytest.mark.parametrize("args", [(0, 1), (129, 1), (True, 1), (16, -1), (16, 2**32)])
def test_experiment_bounds(args):
    with pytest.raises(ValueError):
        run_experiment(*args)


def test_batch_proxy_labels_and_regimes():
    assert batch_work_proxy(256, 1) == 256
    assert batch_work_proxy(255, 256) == 255
    assert batch_work_proxy(257, 256) == 33
    assert batch_work_proxy(65536, 256) == 8192
    assert batch_work_proxy(65536, 4096) == pytest.approx(65536 / 12)
    for args in ((True, 256), (10, 0), (10**10, 256), (16, 256, 29)):
        with pytest.raises(ValueError):
            batch_work_proxy(*args)


def test_browser_math_matches_python_model():
    report = run_experiment(4)
    html = render_html(report)
    script = html.split("<script>")[1].split("</script>")[0]
    function = script.split("function update()")[0]
    cases = [(255, 256), (257, 256), (65536, 256), (65536, 4096), (1024, 65536)]
    program = (
        function
        + "\nconsole.log(JSON.stringify("
        + json.dumps(cases)
        + ".map(([n,b])=>batchWork(n,b))));"
    )
    process = subprocess.run(
        ["node", "-e", program], text=True, capture_output=True, check=True, timeout=10
    )
    assert json.loads(process.stdout) == pytest.approx(
        [batch_work_proxy(*c) for c in cases]
    )
    assert "Insecure research simulator" in html
    assert "not quantum runtimes or universal lower bounds" in html
    assert "__ROWS__" not in html
    assert "<script src=" not in html
