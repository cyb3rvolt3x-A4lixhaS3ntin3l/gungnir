# Stranger path: lab → install gungnir → hunt

End-to-end path for someone who has never used GUNGNIR: stand up the local Juice Shop lab, install the host CLI, run an allowlisted hunt, and read the results.

> **Authorized targets only.** The lab defaults to loopback Juice Shop. Do not point hunts at third-party production hosts without written scope.

## 0) What you need

- Docker + Docker Compose
- Python 3.10+
- ~5 minutes for first lab bring-up

## 1) Lab — Juice Shop on loopback

Clone and start [gungnir-lab](https://github.com/cyb3rvolt3x-A4lixhaS3ntin3l/gungnir-lab):

```bash
git clone https://github.com/cyb3rvolt3x-A4lixhaS3ntin3l/gungnir-lab.git
cd gungnir-lab
docker compose up -d
```

Juice Shop publishes on **127.0.0.1:3000** only (not `0.0.0.0`). Browse http://127.0.0.1:3000 to confirm it is up.

Tear down later with `docker compose down`.

## 2) Install gungnir (host CLI)

From a separate clone of this repo (or a sibling checkout):

```bash
git clone https://github.com/cyb3rvolt3x-A4lixhaS3ntin3l/gungnir.git
cd gungnir
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
gungnir --version
```

PyPI install of `gungnir-security` is **not** the supported path today — install from source as above.

Optional web UI:

```bash
gungnir auth setup
gungnir serve   # http://localhost:8888
```

## 3) Hunt via the lab allowlist

Back in the lab repo, with `gungnir` on your `PATH` (venv activated):

```bash
cd /path/to/gungnir-lab
./scripts/run-lab-hunt.sh
# default target: http://127.0.0.1:3000
```

What the wrapper does:

| Guard | Behavior |
| --- | --- |
| Allowlist | Only `juice-shop`, `juice-shop.lab`, `127.0.0.1`, `localhost` unless `GUNGNIR_LAB_I_OWN_THIS=1` |
| CLI | Invokes `gungnir hunt <url> --json … --report …` |
| Output | Timestamped folder under `./reports/lab-<stamp>/` |

Override target (still allowlisted):

```bash
./scripts/run-lab-hunt.sh http://localhost:3000
```

Owned host outside the default list (you must control it):

```bash
GUNGNIR_LAB_I_OWN_THIS=1 ./scripts/run-lab-hunt.sh http://my-lab.local:3000
```

## 4) Results

After a successful run:

```text
gungnir-lab/reports/lab-YYYYMMDD-HHMMSS/
  results.json    # machine-readable findings
  report.md       # human-readable markdown report
```

Open `report.md` first. Use `results.json` for diffs, CI artifacts, or feeding other tools.

If `gungnir` is missing from `PATH`, the script exits with install hints and leaves the lab target up for browsing.

## 5) Direct CLI (without the wrapper)

Only after you understand the allowlist — same authorized lab target:

```bash
gungnir hunt http://127.0.0.1:3000 --json out.json --report out.md
# or skip external binaries for a quick native-only pass:
gungnir hunt http://127.0.0.1:3000 --no-tools --json out.json --report out.md
```

## Related

- Lab README / demo notes: [gungnir-lab](https://github.com/cyb3rvolt3x-A4lixhaS3ntin3l/gungnir-lab)
- Parent Quick Start: [README.md](../README.md)
- Ethics: authorized / written-scope assessments only
