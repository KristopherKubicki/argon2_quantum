"""Toy QA-KHAPE algebra and attack harness, NOT a deployable PAKE.

Reference: Tiepelt, Eaton, Stebila, ePrint 2023/1513, Figure 1.
The finite group is only 29 bits. Ideal ciphers are private simulator tables;
SHA-256 stands in for random oracles. Seeded randomness is reproducible, not
secret. A classical BSGS solver counts DLog requests; it does not run Shor.
"""

import hashlib
import hmac
import json
import math
import random
from dataclasses import dataclass
from typing import Callable, Hashable

# p and q are prime, p = 2*q+1. g generates the order-q quadratic residues.
P = 1_000_000_007
Q = 500_000_003
G = 4


def frame(domain: str, *values) -> bytes:
    return json.dumps(
        [domain, *values], separators=(",", ":"), ensure_ascii=True
    ).encode()


def digest(domain: str, *values) -> bytes:
    return hashlib.sha256(frame(domain, *values)).digest()


def point(value: int) -> int:
    if type(value) is not int or not 1 <= value < P or pow(value, Q, P) != 1:
        raise ValueError("not a toy subgroup element")
    return value


class IdealCipher:
    """Lazy random bijections on a typed finite domain, for simulation only.

    Tables are part of the ideal-functionality simulator, not attacker-visible
    server credentials. Every wrong-key decryption is a plausible plaintext;
    there is deliberately no authentication tag or decoding validity oracle.
    """

    def __init__(self, rng: random.Random, size: int, sample: Callable[[], Hashable]):
        self.rng = rng
        self.size = size
        self.sample = sample
        self._forward: dict[bytes, dict] = {}
        self._reverse: dict[bytes, dict] = {}

    def _tables(self, key: bytes):
        if not isinstance(key, bytes):
            raise TypeError("ideal cipher key must be bytes")
        return self._forward.setdefault(key, {}), self._reverse.setdefault(key, {})

    def encrypt(self, key: bytes, message: Hashable) -> int:
        forward, reverse = self._tables(key)
        if message not in forward:
            if len(reverse) >= self.size:
                raise RuntimeError("toy ideal-cipher domain exhausted")
            ciphertext = self.rng.randrange(self.size)
            while ciphertext in reverse:
                ciphertext = self.rng.randrange(self.size)
            forward[message] = ciphertext
            reverse[ciphertext] = message
        return forward[message]

    def decrypt(self, key: bytes, ciphertext: int):
        if type(ciphertext) is not int or not 0 <= ciphertext < self.size:
            raise ValueError("invalid toy ciphertext")
        forward, reverse = self._tables(key)
        if ciphertext not in reverse:
            message = self.sample()
            while message in forward:
                message = self.sample()
            reverse[ciphertext] = message
            forward[message] = ciphertext
        return reverse[ciphertext]


@dataclass(frozen=True)
class Context:
    sid: str
    client: str = "synthetic-client"
    server: str = "synthetic-server"

    def fields(self):
        return self.sid, self.client, self.server


@dataclass(frozen=True)
class Credentials:
    b: int
    A: int
    envelope: int
    wrapping_key: int


@dataclass(frozen=True)
class Challenge:
    envelope: int
    Y: int


@dataclass(frozen=True)
class ClientFlight:
    transmitted_X: int
    confirmation: bytes


@dataclass(frozen=True)
class Transcript:
    context: Context
    challenge: Challenge
    client_flight: ClientFlight
    server_confirmation: bytes
    hidden_X: bool


class World:
    """An isolated, seeded ideal-cipher world with synthetic test identities."""

    def __init__(self, seed: int = 20260921):
        self.rng = random.Random(seed)  # nosec B311 - public synthetic experiment
        self.envelopes = IdealCipher(self.rng, Q * Q * 2**128, self._sample_envelope)
        self.group_cipher = IdealCipher(
            self.rng, Q, lambda: pow(G, self.rng.randrange(Q), P)
        )

    def _sample_envelope(self):
        return (
            self.rng.randrange(Q),
            pow(G, self.rng.randrange(Q), P),
            self.rng.getrandbits(128),
        )

    @staticmethod
    def password_key(password: str) -> bytes:
        return frame("password", password)

    @staticmethod
    def wrapping_key(key: int) -> bytes:
        return key.to_bytes(16, "big")

    def register(self, password: str) -> Credentials:
        a, b = self.rng.randrange(Q), self.rng.randrange(Q)
        A, B = pow(G, a, P), pow(G, b, P)
        sk = self.rng.getrandbits(128)
        e = self.envelopes.encrypt(self.password_key(password), (a, B, sk))
        return Credentials(b, A, e, sk)

    def candidate(self, password: str, envelope: int):
        return self.envelopes.decrypt(self.password_key(password), envelope)

    @staticmethod
    def h1(context: Context, element: int) -> int:
        return (
            int.from_bytes(digest("H1", *context.fields(), point(element)), "big") % Q
        )

    @staticmethod
    def h2(context: Context, X: int, Y: int, sigma: int) -> bytes:
        return digest("H2", *context.fields(), point(X), point(Y), point(sigma))

    @staticmethod
    def prf(key: bytes, purpose: int) -> bytes:
        return hmac.digest(key, frame("PRF", purpose), "sha256")

    def client_key(self, context, a, B, x, X, Y) -> bytes:
        hx, hy = self.h1(context, X), self.h1(context, Y)
        sigma = pow(Y * pow(point(B), hy, P) % P, (x + hx * a) % Q, P)
        return self.h2(context, X, Y, sigma)

    def begin(self, credentials: Credentials):
        y = self.rng.randrange(Q)
        return y, Challenge(credentials.envelope, pow(G, y, P))

    def respond(self, context, password, challenge, *, hidden_X=True):
        a, B, sk = self.candidate(password, challenge.envelope)
        x = self.rng.randrange(Q)
        X = pow(G, x, P)
        key = self.client_key(context, a, B, x, X, challenge.Y)
        wire = self.group_cipher.encrypt(self.wrapping_key(sk), X) if hidden_X else X
        return key, ClientFlight(wire, self.prf(key, 1))

    def accept(self, context, credentials, y, challenge, flight, *, hidden_X=True):
        X = (
            self.group_cipher.decrypt(
                self.wrapping_key(credentials.wrapping_key), flight.transmitted_X
            )
            if hidden_X
            else flight.transmitted_X
        )
        hx, hy = self.h1(context, X), self.h1(context, challenge.Y)
        sigma = pow(
            X * pow(point(credentials.A), hx, P) % P,
            (y + hy * credentials.b) % Q,
            P,
        )
        key = self.h2(context, X, challenge.Y, sigma)
        if not hmac.compare_digest(self.prf(key, 1), flight.confirmation):
            return None
        return self.prf(key, 2), self.prf(key, 0)

    def finish(self, client_key: bytes, confirmation: bytes):
        if not hmac.compare_digest(self.prf(client_key, 2), confirmation):
            return None
        return self.prf(client_key, 0)

    def exchange(self, credentials, password, context, *, hidden_X=True):
        y, challenge = self.begin(credentials)
        key, flight = self.respond(context, password, challenge, hidden_X=hidden_X)
        accepted = self.accept(
            context, credentials, y, challenge, flight, hidden_X=hidden_X
        )
        if accepted is None:
            return None
        confirmation, server_key = accepted
        client_key = self.finish(key, confirmation)
        if client_key != server_key:
            raise RuntimeError("honest exchange did not agree")
        return Transcript(context, challenge, flight, confirmation, hidden_X)


class DLogOracle:
    """Classical BSGS with shared baby steps and cached answers, not quantum cost.

    Counts requests separately from distinct target solutions. All guesses use
    the same baby-step table; the toy solver already amortizes classical setup.
    """

    def __init__(self):
        self.requests = 0
        self.unique_targets = 0
        self.giant_steps = 0
        self.width = math.isqrt(Q) + 1
        self._babies = {}
        element = 1
        for i in range(self.width):
            self._babies.setdefault(element, i)
            element = element * G % P
        self._factor = pow(pow(G, self.width, P), -1, P)
        self._cache = {}

    def solve(self, target: int) -> int:
        point(target)
        self.requests += 1
        if target in self._cache:
            return self._cache[target]
        self.unique_targets += 1
        value = target
        for giant in range(self.width + 1):
            self.giant_steps += 1
            if value in self._babies:
                answer = (giant * self.width + self._babies[value]) % Q
                if pow(G, answer, P) == target:
                    self._cache[target] = answer
                    return answer
            value = value * self._factor % P
        raise RuntimeError("DLog solver failed on valid group element")

    def metrics(self):
        return {
            "dlog_requests": self.requests,
            "distinct_dlog_targets": self.unique_targets,
            "classical_baby_steps": self.width,
            "classical_giant_steps": self.giant_steps,
        }


@dataclass(frozen=True)
class AttackResult:
    recovered: str | None
    guesses: int
    metrics: dict


def transcript_attack(world: World, transcript: Transcript, dictionary, oracle):
    """Specific dictionary attack, not a lower-bound claim about all attacks."""
    guesses = 0
    flight, challenge = transcript.client_flight, transcript.challenge
    reused_x = None if transcript.hidden_X else oracle.solve(flight.transmitted_X)
    for password in dictionary:
        guesses += 1
        a, B, sk = world.candidate(password, challenge.envelope)
        X = (
            world.group_cipher.decrypt(world.wrapping_key(sk), flight.transmitted_X)
            if transcript.hidden_X
            else flight.transmitted_X
        )
        x = oracle.solve(X) if transcript.hidden_X else reused_x
        key = world.client_key(transcript.context, a, B, x, X, challenge.Y)
        if hmac.compare_digest(world.prf(key, 1), flight.confirmation):
            return AttackResult(password, guesses, oracle.metrics())
    return AttackResult(None, guesses, oracle.metrics())


def stolen_credentials_attack(world: World, credentials: Credentials, dictionary):
    """DB theft exposes A and sk: guess consistency is classically checkable."""
    guesses = 0
    B = pow(G, credentials.b, P)
    for password in dictionary:
        guesses += 1
        a, candidate_B, sk = world.candidate(password, credentials.envelope)
        if (
            pow(G, a, P) == credentials.A
            and candidate_B == B
            and sk == credentials.wrapping_key
        ):
            return AttackResult(password, guesses, {"dlog_requests": 0})
    return AttackResult(None, guesses, {"dlog_requests": 0})


def confirmation_oracle_attack(envelope: int, tag: bytes, dictionary):
    """Negative control: a password-keyed envelope MAC creates an offline oracle.

    Models the password-checking property an AEAD envelope would introduce;
    it is not an AEAD implementation or a QA-KHAPE construction.
    """
    guesses = 0
    for password in dictionary:
        guesses += 1
        candidate = hmac.digest(
            digest("bad-envelope-key", password), frame("envelope", envelope), "sha256"
        )
        if hmac.compare_digest(candidate, tag):
            return AttackResult(password, guesses, {"dlog_requests": 0})
    return AttackResult(None, guesses, {"dlog_requests": 0})


def known_wrapping_key_attack(world, transcript, sk, dictionary, oracle):
    """Leaking sk restores the reusable public-X attack without leaking a or b."""
    X = world.group_cipher.decrypt(
        world.wrapping_key(sk), transcript.client_flight.transmitted_X
    )
    revealed = Transcript(
        transcript.context,
        transcript.challenge,
        ClientFlight(X, transcript.client_flight.confirmation),
        transcript.server_confirmation,
        False,
    )
    return transcript_attack(world, revealed, dictionary, oracle)


def reusable_static_B_attack(world, transcript, dictionary, oracle):
    """An alternate passive attack that amortizes work across reused credentials.

    Solve Y once per session and candidate B once per credential/password pair.
    Reusing the oracle across sessions reuses the B solutions. This is classical
    algebra with an abstract DLog capability, not the quantum batching algorithm.
    """
    y = oracle.solve(transcript.challenge.Y)
    guesses = 0
    for password in dictionary:
        guesses += 1
        a, B, sk = world.candidate(password, transcript.challenge.envelope)
        X = world.group_cipher.decrypt(
            world.wrapping_key(sk), transcript.client_flight.transmitted_X
        )
        b = oracle.solve(B)
        hx = world.h1(transcript.context, X)
        hy = world.h1(transcript.context, transcript.challenge.Y)
        sigma = pow(
            X * pow(G, hx * a % Q, P) % P,
            (y + hy * b) % Q,
            P,
        )
        key = world.h2(transcript.context, X, transcript.challenge.Y, sigma)
        if hmac.compare_digest(
            world.prf(key, 1), transcript.client_flight.confirmation
        ):
            return AttackResult(password, guesses, oracle.metrics())
    return AttackResult(None, guesses, oracle.metrics())
