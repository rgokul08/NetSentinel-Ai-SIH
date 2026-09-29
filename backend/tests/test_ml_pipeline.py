"""The ML pipeline: normalization, training, evaluation, inference and scoring.

Everything here trains on small synthetic frames in memory - no artifacts are
written and no demo data is touched.
"""

from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from app.ml.features import ATTACK_CLASSES, BENIGN, build_feature_frame, detect_columns, normalize_frame, normalize_label
from app.ml.inference import predict_frame, summarize
from app.ml.scoring import risk_level, risk_score
from app.ml.trainer import evaluate_bundle, train_classifier

PROFILES = {
    "Benign": dict(packet_count=45, byte_count=9_000, destination_port=443, protocol="TCP",
                   tcp_flags="ACK", failed_connections=0, request_frequency=2, flow_duration=9.0,
                   connection_count=3, packet_length=200),
    "DDoS": dict(packet_count=9_500, byte_count=4_200_000, destination_port=80, protocol="TCP",
                 tcp_flags="SYN", failed_connections=420, request_frequency=5_200, flow_duration=1.1,
                 connection_count=900, packet_length=440),
    "Port Scan": dict(packet_count=240, byte_count=15_000, destination_port=22, protocol="TCP",
                      tcp_flags="SYN", failed_connections=190, request_frequency=150, flow_duration=0.6,
                      connection_count=210, packet_length=62),
    "Brute Force": dict(packet_count=640, byte_count=51_000, destination_port=22, protocol="TCP",
                        tcp_flags="PSH", failed_connections=330, request_frequency=95, flow_duration=22.0,
                        connection_count=340, packet_length=80),
}


def synthetic_frame(rows_per_class: int = 55, seed: int = 7) -> pd.DataFrame:
    """Labeled traffic with class signatures the model can actually learn."""
    rng = np.random.default_rng(seed)
    rows = []
    for label, base in PROFILES.items():
        for index in range(rows_per_class):
            jitter = lambda value, spread=0.18: max(0.0, float(value) * float(rng.uniform(1 - spread, 1 + spread)))
            packet_count = int(jitter(base["packet_count"]))
            byte_count = int(jitter(base["byte_count"]))
            rows.append({
                "timestamp": pd.Timestamp("2026-09-28T00:00:00Z") + pd.Timedelta(seconds=int(index * 3)),
                "source_ip": f"10.0.{label == 'Benign' and 1 or 9}.{rng.integers(2, 250)}",
                "destination_ip": f"10.20.30.{rng.integers(2, 60)}",
                "source_port": int(rng.integers(1024, 65000)),
                "destination_port": base["destination_port"],
                "protocol": base["protocol"],
                "packet_count": packet_count,
                "byte_count": byte_count,
                "packet_length": byte_count / max(packet_count, 1),
                "flow_duration": jitter(base["flow_duration"]),
                "packets_per_second": packet_count / max(jitter(base["flow_duration"]), 0.01),
                "bytes_per_second": byte_count / max(jitter(base["flow_duration"]), 0.01),
                "connection_count": int(jitter(base["connection_count"])),
                "tcp_flags": base["tcp_flags"],
                "failed_connections": int(jitter(base["failed_connections"])),
                "request_frequency": jitter(base["request_frequency"]),
                "attack_type": label,
            })
    return pd.DataFrame(rows)


@pytest.fixture(scope="module")
def trained():
    frame = normalize_frame(synthetic_frame())
    bundle, metrics = train_classifier(frame, algorithm="random_forest")
    return frame, bundle, metrics


CIC_IDS_2017_HEADERS = {
    "Flow ID": None, "Src IP": "source_ip", "Src Port": "source_port", "Dst IP": "destination_ip",
    "Dst Port": "destination_port", "Protocol": "protocol", "Timestamp": "timestamp",
    "Flow Duration": "flow_duration", "Tot Fwd Pkts": "packet_count", "TotLen Fwd Pkts": "byte_count",
    "Flow Packets/s": "packets_per_second", "Flow Bytes/s": "bytes_per_second", "Label": "attack_type",
}

CIC_IOT_2023_HEADERS = {
    "sport": "source_port", "dport": "destination_port", "src_ip": "source_ip", "dst_ip": "destination_ip",
    "tot pkts": "packet_count", "tot bytes": "byte_count", "pkts_per_sec": "packets_per_second",
    "duration": "flow_duration", "proto": "protocol", "label": "attack_type",
}


@pytest.mark.parametrize("headers", [CIC_IDS_2017_HEADERS, CIC_IOT_2023_HEADERS])
def test_public_dataset_headers_are_recognized(headers):
    """Real captures (CIC-IDS2017, CICIoT2023) must map onto the canonical schema."""
    frame = pd.DataFrame([{name: 1.0 for name in headers}])
    mapping = detect_columns(frame)["mapping"]
    for name, expected in headers.items():
        if expected:
            assert mapping.get(name) == expected, f"{name!r} should map to {expected!r}, got {mapping.get(name)!r}"


def test_alias_table_has_no_shadowed_keys():
    """A duplicated key in the ALIASES literal silently drops a mapping."""
    import ast
    from collections import Counter
    from pathlib import Path

    import app.ml.features as features

    tree = ast.parse(Path(features.__file__).read_text())
    for node in ast.walk(tree):
        targets = getattr(node, "targets", [])
        if isinstance(node, ast.Assign) and any(getattr(t, "id", None) == "ALIASES" for t in targets):
            keys = [key.value for key in node.value.keys]
            duplicates = [key for key, count in Counter(keys).items() if count > 1]
            assert not duplicates, f"duplicated alias keys: {duplicates}"


def test_messy_headers_are_mapped_onto_the_canonical_schema():
    messy = pd.DataFrame([{
        "Flow Start": "2026-09-28T00:00:00Z", "Src IP": "10.0.0.5", "Dst IP": "10.20.30.9",
        "Src Port": 5123, "Dst Port": 443, "Protocol": "tcp", "Tot pkts": 12, "Tot bytes": 4800,
        "Flow Duration (s)": 3.2, "Label": "BENIGN",
    }])
    detection = detect_columns(messy)
    normalized = normalize_frame(messy, detection)
    for column in ("timestamp", "source_ip", "destination_ip", "source_port", "destination_port",
                   "protocol", "packet_count", "byte_count", "flow_duration", "attack_type"):
        assert column in normalized.columns
    assert normalized.iloc[0]["protocol"] == "TCP"
    assert normalized.iloc[0]["attack_type"] == BENIGN
    assert detection["coverage"] > 0.5


@pytest.mark.parametrize("raw,expected", [
    ("BENIGN", BENIGN), ("normal", BENIGN), ("0", BENIGN), (None, BENIGN), ("", "Network Anomaly"),
    ("DDoS-HULK", "DDoS"), ("PortScan", "Port Scan"), ("Patator SSH", "Brute Force"),
    ("Botnet C2", "Bot Activity"), ("Web Attack – SQL Injection", "Intrusion"),
    ("something-unheard-of", "Network Anomaly"),
])
def test_labels_are_normalized_onto_the_taxonomy(raw, expected):
    assert normalize_label(raw) == expected
    assert expected in ATTACK_CLASSES


def test_training_produces_real_evaluation_artifacts(trained):
    _, _, metrics = trained
    assert metrics["accuracy"] >= 0.9
    assert metrics["training_rows"] == 4 * 55
    assert metrics["test_size"] > 0
    assert metrics["confusion_matrix"]["labels"] and len(metrics["confusion_matrix"]["matrix"]) == len(metrics["confusion_matrix"]["labels"])
    assert {row["class"] for row in metrics["class_report"]} >= {"Benign", "DDoS", "Port Scan", "Brute Force"}
    assert metrics["roc_auc_binary_attack"] is not None and metrics["roc_auc_binary_attack"] >= 0.95
    assert metrics["cv_accuracy_mean"] >= 0.85


def test_bundle_carries_explainability_and_serializable_parts(trained):
    _, bundle, _ = trained
    assert bundle["task"] == "classification"
    assert bundle["algorithm"] == "random_forest"
    assert bundle["feature_names"]
    assert bundle["importance"], "feature importance is required for the XAI panel"
    assert all(0.0 <= abs(item["importance"]) <= 1.0 for item in bundle["importance"][:5])
    assert bundle["preprocessor"].feature_names == bundle["feature_names"]


def test_bundle_can_be_re_evaluated_on_fresh_data(trained):
    frame, bundle, _ = trained
    evaluation = evaluate_bundle(bundle, normalize_frame(synthetic_frame(rows_per_class=20, seed=99)))
    assert "error" not in evaluation
    assert evaluation["accuracy"] >= 0.85
    assert evaluation["rows"] == 80


def test_inference_returns_probabilities_risk_and_explanations(trained):
    frame, bundle, _ = trained
    record = {"id": "unit-test-model", "name": "Unit test forest", "version": "1.0.0", "algorithm": "random_forest"}
    result = predict_frame(frame.head(40), classifier_record=record, classifier_bundle=bundle)

    assert result["model"]["engine"] == "ml"
    assert result["model"]["model_name"] == "Unit test forest"
    predictions = result["predictions"]
    assert len(predictions) == 40
    for prediction in predictions:
        assert prediction["attack_type"] in ATTACK_CLASSES
        # Each class probability is rounded to 4dp, so allow for rounding drift.
        assert sum(prediction["probabilities"].values()) == pytest.approx(1.0, abs=2e-3)
        assert 0.0 <= prediction["attack_probability"] <= 1.0
        assert 0.0 <= prediction["risk_score"] <= 1.0
        assert prediction["risk_level"] in {"informational", "low", "medium", "high", "critical"}
        assert prediction["explanation"], "every prediction must ship an explanation"
    # A model trained on separable signatures should get the held-out rows right.
    correct = sum(1 for p in predictions if p["attack_type"] == p["true_attack_type"])
    assert correct / len(predictions) >= 0.9


def test_inference_without_a_model_falls_back_to_a_labelled_heuristic():
    frame = normalize_frame(synthetic_frame(rows_per_class=5, seed=3))
    result = predict_frame(frame, classifier_record=None, classifier_bundle=None)
    assert result["model"]["engine"] == "heuristic-fallback"
    assert "No trained model is active" in result["model"]["note"]
    assert len(result["predictions"]) == len(frame)


def test_summary_aggregates_predictions(trained):
    frame, bundle, _ = trained
    result = predict_frame(frame.head(30), classifier_bundle=bundle)
    summary = summarize(result["predictions"])
    assert summary["rows"] == 30
    assert summary["attacks_detected"] == sum(v for k, v in summary["class_distribution"].items() if k != BENIGN)
    assert 0.0 <= summary["mean_risk_score"] <= 1.0
    assert summary["class_distribution"] and summary["risk_levels"]
    assert summary["correctness"]["labeled_rows"] == 30
    assert summary["correctness"]["accuracy"] >= 0.9
    assert summarize([]) == {"rows": 0}


@pytest.mark.parametrize("probability,anomaly,attack_type,expected_band", [
    (0.0, 0.0, BENIGN, "informational"),
    (0.35, 0.2, "Port Scan", "medium"),
    (0.8, 0.7, "DDoS", "critical"),
])
def test_risk_scoring_is_bounded_and_monotonic(probability, anomaly, attack_type, expected_band):
    score = risk_score(probability, anomaly, attack_type)
    assert 0.0 <= score <= 1.0
    assert risk_level(score) in {"informational", "low", "medium", "high", "critical"}
    assert risk_score(0.95, 0.9, "DDoS") > risk_score(0.05, 0.05, BENIGN)


def test_risk_bands_are_ordered():
    bands = ["informational", "low", "medium", "high", "critical"]
    scores = [risk_score(p, p, "DDoS") for p in (0.0, 0.25, 0.5, 0.75, 0.99)]
    assert scores == sorted(scores)
    assert all(risk_level(score) in bands for score in scores)


def test_single_row_inference_never_produces_nan_risk():
    """Regression: a one-row frame has no spread, and std() used to yield NaN,
    which serialized to a null risk score and an 'informational' risk level even
    for an obvious DDoS flow."""
    frame = normalize_frame(synthetic_frame(rows_per_class=1, seed=5))
    ddos_row = frame[frame["attack_type"] == "DDoS"]
    result = predict_frame(ddos_row, classifier_record=None, classifier_bundle=None)
    prediction = result["predictions"][0]

    assert prediction["attack_type"] == "DDoS"
    for field in ("anomaly_score", "attack_probability", "risk_score", "confidence"):
        value = prediction[field]
        assert value is not None and value == value, f"{field} must be a real number, got {value!r}"
    assert prediction["risk_level"] in {"high", "critical"}
    assert prediction["is_attack"] is True


def test_scoring_is_nan_safe():
    nan = float("nan")
    assert risk_score(nan, nan, "DDoS") == pytest.approx(0.12, abs=1e-6)
    assert risk_score(0.9, nan, "DDoS") == pytest.approx(risk_score(0.9, 0.0, "DDoS"))
    assert risk_level(nan) == "informational"
    assert risk_level(None) == "informational"
    assert risk_score(None, None, None) == pytest.approx(0.06, abs=1e-6)


def test_feature_frame_is_numeric_and_aligned():
    frame = normalize_frame(synthetic_frame(rows_per_class=4, seed=11))
    matrix, names = build_feature_frame(frame)
    assert len(names) == matrix.shape[1]
    assert np.isfinite(matrix.values.astype(float)).all()
