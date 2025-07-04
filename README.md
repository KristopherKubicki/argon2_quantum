# Argon2 Quantum

This project demonstrates a toy "quantum" pre-hash followed by a classic
memory-hard KDF. The quantum step is simulated and **not** real security.

## Getting Started

Install dependencies and run the CLI to hash a password with a hex salt:

```bash
pip install .
python -m qs_kdf hash mypassword --salt deadbeefcafebabe
```

The output digest can later be verified with the `verify` subcommand:

```bash
python -m qs_kdf verify mypassword --salt deadbeefcafebabe --digest <hex>
```

For an overview of the approach and deployment tips see the documents in
[`docs/`](docs/).

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for
details.
