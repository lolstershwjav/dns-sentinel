"""Unsupervised DNS anomaly scoring; synthetic training data, no network traffic."""
from __future__ import annotations

import csv
import math
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from sklearn.ensemble import IsolationForest

COLUMNS = ("timestamp", "client", "qname", "qtype", "rcode")
FEATURES = ("length", "entropy", "labels", "max_label_length", "digit_fraction", "unique_character_fraction", "is_txt", "is_nxdomain")


@dataclass(frozen=True)
class Query:
    timestamp: str
    client: str
    qname: str
    qtype: str
    rcode: str


def read_queries(path: str | Path) -> list[Query]:
    with open(path, encoding="utf-8", newline="") as stream:
        reader = csv.DictReader(stream)
        missing = set(COLUMNS) - set(reader.fieldnames or ())
        if missing:
            raise ValueError(f"Missing columns: {', '.join(sorted(missing))}")
        queries = []
        for number, row in enumerate(reader, start=2):
            name = (row["qname"] or "").strip().rstrip(".").lower()
            labels = name.split(".")
            if not name or len(name) > 253 or any(not label or len(label) > 63 for label in labels):
                raise ValueError(f"Invalid DNS name at CSV line {number}")
            queries.append(Query(row["timestamp"], row["client"], name, row["qtype"].upper(), row["rcode"].upper()))
    if not queries:
        raise ValueError("No DNS queries found")
    return queries


def entropy(text: str) -> float:
    counts = Counter(text)
    return -sum((count / len(text)) * math.log2(count / len(text)) for count in counts.values()) if text else 0.0


def features(query: Query) -> list[float]:
    name = query.qname
    left = name.split(".")[0]
    return [float(len(name)), entropy(left), float(len(name.split("."))), float(max(map(len, name.split(".")))),
            sum(c.isdigit() for c in left) / len(left), len(set(left)) / len(left),
            float(query.qtype == "TXT"), float(query.rcode == "NXDOMAIN")]


def analyze(baseline: list[Query], observed: list[Query], contamination: float = 0.1) -> list[dict]:
    if len(baseline) < 20:
        raise ValueError("At least 20 baseline queries are required")
    if not 0 < contamination <= 0.5:
        raise ValueError("contamination must be in (0, 0.5]")
    baseline_features = [features(q) for q in baseline]
    model = IsolationForest(n_estimators=150, contamination=contamination, random_state=42)
    model.fit(baseline_features)
    scores = model.decision_function([features(q) for q in observed])
    predictions = model.predict([features(q) for q in observed])
    results = []
    for query, score, pred in zip(observed, scores, predictions):
        f = dict(zip(FEATURES, features(query)))
        reasons = []
        if f["max_label_length"] >= 45:
            reasons.append("long DNS label")
        if f["entropy"] >= 3.8 and f["length"] >= 45:
            reasons.append("high-entropy long name")
        if query.qtype == "TXT" and f["length"] >= 45:
            reasons.append("long TXT lookup")
        if query.rcode == "NXDOMAIN" and f["length"] >= 45:
            reasons.append("long failed lookup")
        flagged = bool(pred == -1 or reasons)
        results.append({"timestamp": query.timestamp, "client": query.client, "qname": query.qname,
                        "qtype": query.qtype, "rcode": query.rcode, "anomaly": flagged,
                        "score": round(float(score), 5), "reasons": reasons, "features": f})
    return results
