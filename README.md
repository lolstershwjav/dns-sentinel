# DNS Sentinel

Offline DNS telemetry anomaly triage using **Isolation Forest** and explainable DNS-name heuristics. Built as a defensive security engineering demonstration: it reads CSV exports, extracts lexical features, scores unusual DNS queries, and produces JSON findings. It **does not** send network traffic or resolve any domains.

## Run

Requires Python 3.10+.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
dns-sentinel --baseline data/baseline.csv --observed data/observed.csv --output findings.json
pytest -q
```

On Windows, activate with `.venv\Scripts\activate`.

## Input

Both CSVs require `timestamp,client,qname,qtype,rcode`. The supplied addresses use documentation-only IP space and the queries are synthetic. The baseline should represent known normal behavior. The sample includes unusually long, encoded-looking names and TXT lookups.

## How it works

The detector calculates query length, first-label Shannon entropy, number of labels, longest label, digit fraction, unique-character fraction, TXT indicator, and NXDOMAIN indicator. An Isolation Forest learns the baseline distribution. Conservative, explainable rules flag unusually long labels, long high-entropy names, and long TXT/NXDOMAIN lookups. Results include a model score and reason labels.

## Security and limitations

A flag is **not** proof of DNS tunneling or compromise. Legitimate telemetry, CDNs, and security tools can produce high-entropy names; sophisticated tunneling can use short names. This is a proof of concept with no labeled benchmark, so accuracy, precision, and recall are **not established**. Evaluate against authorized, representative data before operational use. Do not commit real DNS logs containing sensitive domains or client identifiers. Keep reports private when using production telemetry.

## Layout

- `src/dnssentinel/detector.py` — validation, feature extraction, scoring
- `src/dnssentinel/cli.py` — command-line interface
- `tests/` — pytest coverage
- `data/` — synthetic CSVs

## License

MIT
