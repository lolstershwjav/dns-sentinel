import pytest
from dnssentinel.detector import Query, analyze, entropy, features, read_queries


def q(name="www.example.com", qtype="A", rcode="NOERROR"):
    return Query("2026-11-17T12:00:00Z", "192.0.2.10", name, qtype, rcode)


def baseline():
    names = ["www", "mail", "docs", "api", "static", "cdn", "portal", "status", "help", "news"]
    return [q(f"{names[i % 10]}{i % 3}.example.com") for i in range(60)]


def test_entropy():
    assert entropy("aaaa") == 0
    assert entropy("abcd") == pytest.approx(2.0)


def test_features_length():
    assert features(q())[0] == len("www.example.com")


def test_long_label_is_flagged():
    suspect = q("a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4.example.com", "TXT")
    result = analyze(baseline(), [suspect])[0]
    assert result["anomaly"] is True
    assert "long DNS label" in result["reasons"]


def test_result_schema():
    result = analyze(baseline(), [q()])[0]
    assert isinstance(result["score"], float)
    assert "features" in result


def test_reject_small_baseline():
    with pytest.raises(ValueError, match="20 baseline"):
        analyze([q()], [q()])


def test_reject_contamination():
    with pytest.raises(ValueError, match="contamination"):
        analyze(baseline(), [q()], 0)


def test_invalid_csv(tmp_path):
    p = tmp_path / "bad.csv"
    p.write_text("timestamp,client,qname,qtype,rcode\nnow,client," + "a" * 64 + ".example.com,A,NOERROR\n")
    with pytest.raises(ValueError, match="Invalid DNS name"):
        read_queries(p)


def test_missing_columns(tmp_path):
    p = tmp_path / "bad.csv"
    p.write_text("qname\nexample.com\n")
    with pytest.raises(ValueError, match="Missing columns"):
        read_queries(p)
