# ruff: noqa: E501
# HTML template lines retain readable element boundaries.
"""Self-contained, offline research report. Numbers remain labeled by model."""

import html

from .experiment import report_digest


TEMPLATE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Quantum Annoying — attack lab</title>
<style>
:root{font-family:system-ui,sans-serif;color:#17212e;background:#f4f3ef;line-height:1.6}
*{box-sizing:border-box}body{margin:0}main{max-width:1080px;margin:auto;padding:48px 24px 72px}
.label{letter-spacing:.15em;text-transform:uppercase;font-size:12px;font-weight:750;color:#675741}
h1{font-size:clamp(38px,7vw,76px);line-height:1.08;letter-spacing:-.055em;margin:12px 0 20px}
h2{font-size:24px;line-height:1.3;margin:0 0 14px}p{max-width:78ch}.lead{font-size:21px;color:#455365}
.notice{border-left:4px solid #ab6400;background:#fff0d2;padding:16px 20px;margin:26px 0}
.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:16px}.card,section{background:#fff;border:1px solid #deded8;border-radius:12px;padding:24px}
.card strong{display:block;font-size:34px;line-height:1.25}.card span{color:#526071;font-size:14px}
section{margin-top:22px}small,.muted{color:#596776}table{width:100%;border-collapse:collapse;font-size:15px}
th,td{text-align:left;padding:12px 8px;border-bottom:1px solid #e5e7eb}th{font-weight:650;color:#536171}
.scroll{overflow:auto}.barrow{display:grid;grid-template-columns:minmax(180px,2fr) 3fr 50px;gap:12px;align-items:center;margin:14px 0;font-size:14px}
.track{height:14px;background:#edece7;border-radius:4px}.fill{height:100%;background:#a86105;border-radius:4px}.barrow:nth-child(2) .fill{background:#1d5960}
.controls{display:flex;gap:30px;flex-wrap:wrap;margin:18px 0}label{display:block;font-weight:600}input,select{font:inherit;max-width:100%}input[type=range]{width:260px;display:block}
.output{display:flex;gap:36px;flex-wrap:wrap;background:#f4f6f7;padding:18px;border-radius:8px}.output strong{font-size:28px;display:block}
code{font-size:13px;overflow-wrap:anywhere}a{color:#20566a}li{margin-bottom:8px}footer{margin-top:28px;font-size:13px;color:#596776}
@media(max-width:680px){main{padding:28px 16px}.grid{grid-template-columns:1fr}.barrow{grid-template-columns:1fr 1fr 32px}.card,section{padding:18px}}
</style></head><body><main>
<div class="label">Research notebook / 01</div>
<h1>Quantum Annoying.</h1>
<p class="lead">Make password guessing repeat expensive work. Then look for every way an attacker can reuse it.</p>
<div class="notice"><strong>Insecure research simulator.</strong> This is a 29-bit toy group with public seeded randomness and ideal-cipher tables. It runs classical attacks on synthetic data. It does not run quantum hardware, prove security, or implement a deployable login protocol.</div>
<div class="grid">
<div class="card"><strong>__GUESSES__</strong><span>Synthetic guesses; correct password is last</span></div>
<div class="card"><strong>0 QPU calls</strong><span>Honest handshake and all experiments run classically</span></div>
<div class="card"><strong>__ADDED__ new target</strong><span>Second session, with candidate static-key solutions reused</span></div>
</div>
<section><h2>The attack comparison</h2>
<p>Observed distinct discrete-log targets for these specific attacks. The oracle uses a classical baby-step giant-step solver with a shared setup table. These counts are <strong>not quantum runtimes or universal lower bounds</strong>.</p>
<div aria-label="Observed attack target counts">__BARS__</div>
<div class="scroll"><table><thead><tr><th>Attack scenario</th><th>Guesses</th><th>DLog requests</th><th>Distinct targets</th></tr></thead><tbody>__ROWS__</tbody></table></div>
<p class="muted">Public-X is an ablation of the model: one solved exponent can be reused. Hidden-X makes this dictionary attack solve candidate-dependent targets. A leaked wrapping key restores the one-target attack. Stolen credentials and a password-confirming envelope permit classical checks.</p>
</section>
<section><h2>The reuse attack is part of the result</h2>
<p>The alternate attack solves each candidate’s static server public key once, caches the result, and solves one fresh server ephemeral per session. With reused credentials, the second session adds just <strong>__ADDED__</strong> new target here. Session binding prevents replay; it does not eliminate this amortization.</p>
<p>Two-session totals: <strong>__TOTAL__ distinct targets</strong> across <strong>__CROSS_GUESSES__ dictionary guesses</strong>. Do not advertise one independent full-cost quantum run for every guess in every session.</p>
</section>
<section><h2>Quantum batching: a sensitivity exercise</h2>
<p>Published work gives an asymptotic multiple-logarithm algorithm with an <code>m / log₂(m)</code> factor relative to the group-size term. Explore that shape below. The calculation normalizes an independent solve to one arbitrary unit and omits constants, quantum memory, error correction and hardware costs. <strong>These are illustrative units, not predicted speedups.</strong></p>
<div class="controls">
<div><label for="rank">Hypothetical guesses: <output id="rank-value">65,536</output></label><input id="rank" type="range" min="8" max="20" value="16" step="1"></div>
<div><label for="batch">Simultaneous batch</label><select id="batch"><option value="1">No batching</option><option value="256" selected>256 targets</option><option value="4096">4,096 targets</option><option value="65536">65,536 targets</option></select></div>
</div>
<div class="output" aria-live="polite"><div><small>Independent scenario units</small><strong id="serial">65,536</strong></div><div><small>Batch-shaped scenario units</small><strong id="batched">8,192</strong></div></div>
<p class="muted">Assumed group size is approximately 2²⁵⁶. Batches below 256 and small remainders use the independent scenario. The theorem is asymptotic; satisfying one size threshold does not establish a finite hardware cost or a guaranteed improvement. This panel is separate from the measured toy-group table.</p>
<noscript><p>The initial scenario is shown above. Enable JavaScript to change the assumptions.</p></noscript>
</section>
<section><h2>What this earns us—and what it doesn’t</h2>
<ul><li>A working model of mutual key confirmation and candidate-dependent transcript attacks.</li>
<li>Executable failure cases for public handshake values, leaked credentials, and password-confirming envelopes.</li>
<li>A concrete cross-session amortization attack to include in future analysis.</li>
<li>No claim of post-quantum security, database-theft resistance, constant-time code, or a general quantum lower bound.</li></ul>
<p>The next hard problem is a concrete cipher/encoding that preserves wrong-password ambiguity, followed by analysis against broader quantum algorithms and compromised-state attacks. Replacing the simulator tables with ordinary authenticated encryption is not a safe shortcut.</p>
</section>
<section><h2>Reproduce and inspect</h2><p><code>python -m research.quantum_annoying --guesses __GUESSES__ --seed __SEED__</code></p>
<p>Report SHA-256: <code>__DIGEST__</code></p><p><a href="experiment.json">Download the underlying JSON</a></p>
<ul>__SOURCES__</ul></section>
<footer>Quantum Annoying Lab · Source-only experiment, excluded from the production wheel · No network requests or remote assets in this report.</footer>
</main>
<script>
"use strict";
function batchWork(n,b){if(b<256)return n;const full=Math.floor(n/b),tail=n%b;return full*b/Math.log2(b)+(tail<256?tail:tail/Math.log2(tail));}
function update(){const n=2**Number(document.getElementById('rank').value),b=Number(document.getElementById('batch').value);document.getElementById('rank-value').textContent=n.toLocaleString('en-US');document.getElementById('serial').textContent=n.toLocaleString('en-US');document.getElementById('batched').textContent=batchWork(n,b).toLocaleString('en-US',{maximumFractionDigits:1});}
document.getElementById('rank').addEventListener('input',update);document.getElementById('batch').addEventListener('change',update);update();
</script></body></html>"""


def render_html(report: dict) -> str:
    counts = [c["metrics"].get("distinct_dlog_targets", 0) for c in report["cases"]]
    scale = max(counts + [1])
    rows, bars = [], []
    for case, count in zip(report["cases"], counts, strict=True):
        name = html.escape(case["name"])
        requests = case["metrics"]["dlog_requests"]
        rows.append(
            f"<tr><td>{name}</td><td>{case['guesses']}</td><td>{requests}</td><td>{count}</td></tr>"
        )
        bars.append(
            f'<div class="barrow"><span>{name}</span><div class="track">'
            f'<div class="fill" style="width:{100 * count / scale:.2f}%"></div>'
            f"</div><strong>{count}</strong></div>"
        )
    cross = report["cross_session"]
    substitutions = {
        "GUESSES": report["dictionary_size"],
        "SEED": report["seed"],
        "ADDED": cross["distinct_targets_added_second_session"],
        "TOTAL": cross["cumulative"]["distinct_dlog_targets"],
        "CROSS_GUESSES": cross["dictionary_guesses_total"],
        "DIGEST": report_digest(report),
        "ROWS": "".join(rows),
        "BARS": "".join(bars),
        "SOURCES": "".join(
            f'<li><a href="{html.escape(s["url"], quote=True)}">{html.escape(s["title"])}</a></li>'
            for s in report["sources"]
        ),
    }
    result = TEMPLATE
    for key, value in substitutions.items():
        result = result.replace(f"__{key}__", str(value))
    return result
