# Optional quantum entropy experiment

`BraketBackend` prepares eight qubits with Hadamard gates and measures each in the
computational basis. It requests ten shots by default, validates the number and
width of measurement rows, and converts each row to a byte in shot order.
Count histograms are not expanded into ordered measurements: doing so groups
repeated outcomes and changes the sequence distribution.

In an ideal noiseless model these are independent uniform bits. Real hardware
has noise and bias; the adapter provides no randomness certification, entropy
estimation, health test, or attestation. Some devices/results may derive samples
from probabilities. See [AWS result semantics](https://docs.aws.amazon.com/braket/latest/developerguide/braket-result-types.html).

The circuit is efficiently classically simulable and ignores the supplied legacy
seed argument. It does not force an attacker to use quantum hardware or buy AWS
calls. Optional use in v0.2 only supplements mandatory OS randomness when forming
the public salt. Do not use this adapter alone to generate encryption keys.

An explicit device ARN is required; there is no assumed current IonQ device.
Install the quantum extra and configure AWS credentials. Initialization failures
are retained and raised as RuntimeError when run is attempted. Execution or
malformed measurements fail closed, with no fake-randomness fallback. The adapter
bounds shot requests to 1–4096 and waits at most 120 seconds via the SDK polling
option. Account permissions, budgets, and device availability remain operator
responsibilities. This path was tested with mocks, not paid live hardware.

The legacy LocalBackend is deterministic SHA-512, not a quantum simulator. It is
kept solely for reproducing old local hashes. New local enrollment uses the
operating system's cryptographic randomness.
