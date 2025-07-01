# Argon2 Quantum

This project demonstrates a toy "quantum" pre-hash followed by a classic
memory-hard KDF. The quantum step is simulated and **not** real security.

## Usage

```bash
python qsargon2.py mypassword --salt deadbeefcafebabe
```

The script prints a Base64 digest derived from the password, salt and a fixed
pepper. The `qsargon2.qstretch` function is deterministic and unit tested.
```

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for
details.

