"""
Security report generation (PDF + CSV).

Reports are assembled from live analytics data: traffic summary, attack summary,
anomaly statistics, forecast results, critical alerts, model performance and the
blockchain verification summary.
"""

from __future__ import annotations

import csv
import io
import logging
import os
from typing import Any, Dict, List, Optional, Tuple

from app.blockchain import ledger
from app.core.config import settings
from app.core.paths import get_reports_dir
from app.core.utils import compact_number, iso, new_id, safe_float, utcnow
from app.services import alert_service, analytics_service, forecast_service, model_service, traffic_service
from app.storage import get_store

logger = logging.getLogger("cyberforecast.reports")

ACCENT = (0.13, 0.77, 0.90)      # cyan
DARK = (0.05, 0.07, 0.12)
MUTED = (0.45, 0.52, 0.62)


class ReportError(Exception):
    def __init__(self, message: str, status_code: int = 400) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code


def build_report_data(window: str = "24h", report_type: str = "security_summary") -> Dict[str, Any]:
    overview = analytics_service.overview(window)
    trends = analytics_service.trends(window)
    traffic = traffic_service.summary(window)
    alerts = alert_service.stats()
    integrity = ledger.stats()
    registry = model_service.registry_status()

    critical_alerts, _ = alert_service.list_alerts(limit=15, severity="critical", order_by="-timestamp")
    high_alerts, _ = alert_service.list_alerts(limit=10, severity="high", order_by="-timestamp")
    top_entities = analytics_service.top_entities(window, limit=8)

    try:
        forecast = forecast_service.latest_run()
    except Exception:  # pragma: no cover
        forecast = None

    return {
        "report_type": report_type,
        "window": window,
        "generated_at": iso(utcnow()),
        "overview": overview,
        "trends": trends,
        "traffic": traffic,
        "alerts": alerts,
        "critical_alerts": critical_alerts,
        "high_alerts": high_alerts,
        "blockchain": integrity,
        "model_registry": registry,
        "forecast": forecast,
        "top_entities": top_entities,
        "chain_verification": ledger.verify_chain(max_entries=200),
    }


# ---------------------------------------------------------------------------
# PDF rendering
# ---------------------------------------------------------------------------

def render_pdf(data: Dict[str, Any], title: str) -> bytes:
    from reportlab.graphics.charts.barcharts import HorizontalBarChart
    from reportlab.graphics.charts.lineplots import LinePlot
    from reportlab.graphics.shapes import Drawing, String
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_LEFT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle, KeepTogether,
    )

    buffer = io.BytesIO()
    styles = getSampleStyleSheet()
    h1 = ParagraphStyle("h1", parent=styles["Heading1"], textColor=colors.Color(*DARK), fontSize=17, spaceAfter=4)
    h2 = ParagraphStyle("h2", parent=styles["Heading2"], textColor=colors.Color(*ACCENT), fontSize=12, spaceBefore=12, spaceAfter=4)
    body = ParagraphStyle("body", parent=styles["BodyText"], fontSize=9, leading=12.5, textColor=colors.Color(0.15, 0.18, 0.24))
    small = ParagraphStyle("small", parent=body, fontSize=7.6, textColor=colors.Color(*MUTED))
    centered = ParagraphStyle("centered", parent=body, alignment=TA_CENTER)

    def _table(rows: List[List[Any]], widths: Optional[List[float]] = None, header: bool = True) -> Table:
        table = Table(rows, colWidths=widths, repeatRows=1 if header else 0, hAlign="LEFT")
        style = [
            ("FONTSIZE", (0, 0), (-1, -1), 8.2),
            ("GRID", (0, 0), (-1, -1), 0.35, colors.Color(0.85, 0.88, 0.92)),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 3.5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5),
        ]
        if header:
            style += [
                ("BACKGROUND", (0, 0), (-1, 0), colors.Color(*DARK)),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.Color(0.96, 0.98, 0.99)]),
            ]
        table.setStyle(TableStyle(style))
        return table

    def _footer(canvas, doc):
        canvas.saveState()
        canvas.setStrokeColor(colors.Color(0.85, 0.88, 0.92))
        canvas.setLineWidth(0.5)
        canvas.line(18 * mm, 14 * mm, A4[0] - 18 * mm, 14 * mm)
        canvas.setFont("Helvetica", 7.2)
        canvas.setFillColor(colors.Color(*MUTED))
        canvas.drawString(18 * mm, 10 * mm, "CyberForecast AI - AI-Based Network Attack Forecasting & Blockchain-Assured Cybersecurity")
        canvas.drawRightString(A4[0] - 18 * mm, 10 * mm, f"Page {doc.page}")
        canvas.restoreState()

    doc = SimpleDocTemplate(
        buffer, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm,
        topMargin=16 * mm, bottomMargin=20 * mm, title=title, author="CyberForecast AI",
    )
    story: List[Any] = []
    overview = data["overview"]
    kpis = overview.get("kpis", {})
    traffic = data["traffic"]

    # --- header -----------------------------------------------------------
    story.append(Paragraph(title, h1))
    story.append(Paragraph(
        f"Reporting window: <b>{data['window']}</b> &nbsp;|&nbsp; Generated: {data['generated_at']} &nbsp;|&nbsp; "
        f"Backend: {settings.storage_backend} &nbsp;|&nbsp; Integrity layer: {data['blockchain'].get('anchor_mode')}",
        small))
    story.append(Spacer(1, 6))

    story.append(Paragraph("1. Executive summary", h2))
    threat = str(overview.get("threat_level", "informational")).upper()
    forecast_summary = ""
    if data.get("forecast") and data["forecast"].get("overall"):
        overall = data["forecast"]["overall"]
        top = overall.get("top_threat") or {}
        forecast_summary = (
            f" The {overall.get('horizon_minutes')}-minute forecast estimates a "
            f"{round(safe_float(overall.get('probability')) * 100, 1)}% probability of attack activity "
            f"(leading category: {top.get('attack_type', 'n/a')}, confidence {top.get('confidence')})."
        )
    story.append(Paragraph(
        f"Across the reporting window the platform analyzed <b>{kpis.get('flows', 0):,}</b> network flows "
        f"({compact_number(kpis.get('packets', 0))} packets, {compact_number(kpis.get('traffic_bytes', 0))} bytes). "
        f"Detection produced <b>{kpis.get('detected_threats', 0):,}</b> attack verdicts and "
        f"<b>{kpis.get('anomalies', 0):,}</b> statistical anomalies; "
        f"<b>{data['alerts'].get('critical_open', 0)}</b> critical alerts remain open. "
        f"Overall threat level is <b>{threat}</b> (current risk score "
        f"{round(safe_float(kpis.get('current_risk_score')) * 100, 1)}/100).{forecast_summary} "
        f"{round(data['blockchain'].get('verified_percentage', 0), 1)}% of ledger entries pass integrity verification.",
        body))
    story.append(Paragraph(
        "All figures are computed from persisted records at generation time. "
        f"Simulated traffic share: {overview.get('data_origin', {}).get('simulated_percentage', 0)}%.",
        small))

    # --- KPI table --------------------------------------------------------
    story.append(Paragraph("2. Key performance indicators", h2))
    kpi_rows = [
        ["Metric", "Value", "Metric", "Value"],
        ["Network packets", compact_number(kpis.get("packets", 0)), "Detected threats", f"{kpis.get('detected_threats', 0):,}"],
        ["Traffic volume", compact_number(kpis.get("traffic_bytes", 0)) + "B", "Critical alerts (open)", data["alerts"].get("critical_open", 0)],
        ["Throughput", f"{kpis.get('traffic_mbps', 0)} Mbps", "Anomalies", f"{kpis.get('anomalies', 0):,}"],
        ["Active connections", f"{kpis.get('active_connections', 0):,}", "Forecasted attacks (60m)", kpis.get("forecasted_attacks", 0)],
        ["Unique sources", f"{kpis.get('unique_sources', 0):,}", "Current risk score", f"{round(safe_float(kpis.get('current_risk_score')) * 100, 1)}/100"],
        ["Unique destinations", f"{kpis.get('unique_destinations', 0):,}", "Abnormal traffic", f"{kpis.get('abnormal_percentage', 0)}%"],
        ["Failed connections", f"{kpis.get('failed_connections', 0):,}", "Threat level", threat],
    ]
    story.append(_table(kpi_rows, widths=[42 * mm, 32 * mm, 48 * mm, 40 * mm]))

    # --- attack summary ---------------------------------------------------
    story.append(Paragraph("3. Attack summary", h2))
    distribution = overview.get("attack_distribution") or []
    if distribution:
        rows = [["Attack category", "Events", "Share of flows"]]
        total_flows = max(kpis.get("flows", 1), 1)
        for item in sorted(distribution, key=lambda x: x["value"], reverse=True):
            rows.append([item["name"], f"{item['value']:,}", f"{round(item['value'] / total_flows * 100, 2)}%"])
        story.append(_table(rows, widths=[60 * mm, 30 * mm, 40 * mm]))

        drawing = Drawing(170 * mm, 46 * mm)
        chart = HorizontalBarChart()
        chart.x, chart.y, chart.width, chart.height = 42 * mm, 8 * mm, 120 * mm, 32 * mm
        labels = [item["name"] for item in sorted(distribution, key=lambda x: x["value"])]
        values = [item["value"] for item in sorted(distribution, key=lambda x: x["value"])]
        chart.data = [values]
        chart.categoryAxis.categoryNames = labels
        chart.categoryAxis.labels.fontSize = 6.5
        chart.valueAxis.labels.fontSize = 6.5
        chart.valueAxis.valueMin = 0
        chart.bars[0].fillColor = colors.Color(*ACCENT)
        chart.bars.strokeColor = None
        chart.barLabels.fontSize = 6.5
        chart.barLabelFormat = "%d"
        chart.barLabels.nudge = 6
        drawing.add(chart)
        drawing.add(String(4 * mm, 22 * mm, "Events", fontSize=7, fillColor=colors.Color(*MUTED)))
        story.append(drawing)
    else:
        story.append(Paragraph("No attack verdicts were recorded in this window.", body))

    severity = data["alerts"].get("by_severity") or {}
    if severity:
        rows = [["Severity", "Alerts"]] + [[k.title(), f"{v:,}"] for k, v in severity.items() if v]
        story.append(Spacer(1, 4))
        story.append(_table(rows, widths=[50 * mm, 30 * mm]))

    # --- traffic trend ----------------------------------------------------
    story.append(Paragraph("4. Traffic and anomaly trend", h2))
    series = data["trends"].get("attacks_over_time") or []
    if len(series) > 1:
        drawing = Drawing(170 * mm, 52 * mm)
        plot = LinePlot()
        plot.x, plot.y, plot.width, plot.height = 14 * mm, 12 * mm, 150 * mm, 34 * mm
        attacks = [(index, item["attacks"]) for index, item in enumerate(series)]
        anomalies = [(index, item.get("anomalies", 0)) for index, item in enumerate(
            (data["trends"].get("anomaly_trend") or series))]
        plot.data = [attacks, anomalies]
        plot.lines[0].strokeColor = colors.Color(0.96, 0.26, 0.37)
        plot.lines[1].strokeColor = colors.Color(*ACCENT)
        plot.lines.strokeWidth = 1.2
        plot.xValueAxis.labels.fontSize = 6.5
        plot.yValueAxis.labels.fontSize = 6.5
        plot.xValueAxis.valueMin, plot.xValueAxis.valueMax = 0, len(series) - 1
        plot.xValueAxis.labelTextFormat = "%d"
        drawing.add(plot)
        drawing.add(String(14 * mm, 48 * mm, "Attacks (red) / anomalies (cyan) per time bucket", fontSize=7,
                           fillColor=colors.Color(*MUTED)))
        story.append(drawing)
    story.append(Paragraph(
        f"Peak throughput {traffic.get('packets_per_second', 0)} packets/s and "
        f"{round(traffic.get('bytes_per_second', 0) / 1024, 1)} KB/s; mean flow risk score "
        f"{round(safe_float(traffic.get('mean_risk_score')) * 100, 1)}/100.", body))

    correctness = data["trends"].get("correctness")
    if correctness:
        story.append(Paragraph("Detection quality against ground truth (labeled rows only)", h2))
        story.append(_table([
            ["Labeled rows", "True positives", "False positives", "True negatives", "False negatives", "Precision", "Recall"],
            [f"{correctness['labeled_rows']:,}", correctness["true_positives"], correctness["false_positives"],
             correctness["true_negatives"], correctness["false_negatives"],
             f"{round(correctness['precision'] * 100, 1)}%", f"{round(correctness['recall'] * 100, 1)}%"],
        ], widths=[24 * mm, 26 * mm, 26 * mm, 26 * mm, 26 * mm, 22 * mm, 22 * mm]))

    story.append(PageBreak())

    # --- forecast ---------------------------------------------------------
    story.append(Paragraph("5. Attack forecast", h2))
    forecast = data.get("forecast")
    if forecast and forecast.get("horizons"):
        rows = [["Horizon", "Leading threat", "Probability", "Risk", "Confidence", "Expected events"]]
        for horizon in forecast["horizons"]:
            top = horizon.get("top_threat") or {}
            rows.append([
                f"{horizon.get('horizon_minutes')} min", top.get("attack_type", "-"),
                f"{round(safe_float(horizon.get('overall_probability')) * 100, 1)}%",
                str(horizon.get("overall_risk_level", "-")).upper(),
                horizon.get("overall_confidence", "-"),
                horizon.get("expected_attack_events", 0),
            ])
        story.append(_table(rows, widths=[22 * mm, 38 * mm, 26 * mm, 24 * mm, 26 * mm, 30 * mm]))
        longest = forecast["horizons"][-1]
        category_rows = [["Category", "Probability", "Per-bucket", "Expected", "95% interval", "Risk", "Method"]]
        for category in longest.get("categories", []):
            category_rows.append([
                category.get("attack_type", "-"),
                f"{round(safe_float(category.get('probability')) * 100, 1)}%",
                f"{round(safe_float(category.get('per_bucket_probability')) * 100, 1)}%",
                category.get("expected_events", 0),
                f"[{category.get('lower_bound', 0)}, {category.get('upper_bound', 0)}]",
                str(category.get("risk_level", "-")).upper(),
                category.get("method", "-"),
            ])
        story.append(Spacer(1, 4))
        story.append(_table(category_rows, widths=[32 * mm, 22 * mm, 22 * mm, 20 * mm, 28 * mm, 20 * mm, 30 * mm]))
        top = longest.get("top_threat") or {}
        if top.get("recommendation"):
            story.append(Spacer(1, 3))
            story.append(Paragraph(f"<b>Recommended action ({top.get('attack_type')}):</b> {top['recommendation']}", body))
        story.append(Paragraph(
            forecast.get("disclaimer", "Forecasts are probabilistic estimates, not certainties."), small))
    else:
        story.append(Paragraph("No forecast run is available for this window.", body))

    # --- critical alerts --------------------------------------------------
    story.append(Paragraph("6. Critical and high-severity alerts", h2))
    alert_rows = [["Code", "Time", "Severity", "Attack", "Risk", "Status", "Source -> Target"]]
    for alert in (data.get("critical_alerts") or [])[:12] + (data.get("high_alerts") or [])[:8]:
        alert_rows.append([
            alert.get("alert_code", ""), (alert.get("timestamp") or "")[:19].replace("T", " "),
            str(alert.get("severity", "")).upper(), alert.get("attack_type", ""),
            f"{round(safe_float(alert.get('risk_score')) * 100, 0):.0f}", alert.get("status", ""),
            f"{alert.get('source_ip', '-')} -> {alert.get('destination_ip', '-')}",
        ])
    if len(alert_rows) > 1:
        story.append(_table(alert_rows, widths=[26 * mm, 28 * mm, 20 * mm, 26 * mm, 12 * mm, 20 * mm, 44 * mm]))
    else:
        story.append(Paragraph("No critical or high-severity alerts in this window.", body))

    # --- model performance ------------------------------------------------
    story.append(Paragraph("7. Model performance", h2))
    registry = data["model_registry"]
    classifier = registry.get("active_classifier") or {}
    anomaly = registry.get("active_anomaly_detector") or {}
    model_rows = [["Property", "Active classifier", "Active anomaly detector"]]
    model_rows += [
        ["Name", classifier.get("name", "none"), anomaly.get("name", "none")],
        ["Algorithm", classifier.get("algorithm", "-"), anomaly.get("algorithm", "-")],
        ["Version", classifier.get("version", "-"), anomaly.get("version", "-")],
        ["Training rows", classifier.get("training_rows", "-"), anomaly.get("training_rows", "-")],
        ["Accuracy", classifier.get("accuracy", "-"), anomaly.get("metrics", {}).get("attack_recall", "-") if anomaly else "-"],
        ["Precision (weighted)", classifier.get("precision_score", "-"), "-"],
        ["Recall (weighted)", classifier.get("recall_score", "-"), "-"],
        ["F1 (weighted)", classifier.get("f1_score", "-"), "-"],
        ["ROC-AUC (OvR)", classifier.get("roc_auc", "-"), "-"],
        ["Trained at", (classifier.get("trained_at") or "-")[:19].replace("T", " "),
         (anomaly.get("trained_at") or "-")[:19].replace("T", " ")],
    ]
    story.append(_table(model_rows, widths=[38 * mm, 62 * mm, 62 * mm]))
    class_report = (classifier.get("class_report") or [])[:10]
    if class_report:
        rows = [["Class", "Precision", "Recall", "F1", "Support"]]
        for item in class_report:
            rows.append([item["class"], item["precision"], item["recall"], item["f1"], item["support"]])
        story.append(Spacer(1, 4))
        story.append(Paragraph("Per-class performance (held-out test split)", small))
        story.append(_table(rows, widths=[40 * mm, 26 * mm, 26 * mm, 26 * mm, 26 * mm]))
    story.append(Paragraph(
        "Metrics are computed on a held-out test split of the training dataset. Synthetic sample data is highly "
        "separable, so per-class macro metrics are the more meaningful indicator.", small))

    # --- blockchain -------------------------------------------------------
    story.append(Paragraph("8. Blockchain integrity summary", h2))
    integrity = data["blockchain"]
    chain = data["chain_verification"]
    story.append(_table([
        ["Ledger entries", "Verified", "Pending", "Failed", "Verified %", "Anchor mode", "Chain intact"],
        [f"{integrity.get('total_events', 0):,}", integrity.get("verified", 0), integrity.get("pending", 0),
         integrity.get("failed", 0), f"{integrity.get('verified_percentage', 0)}%",
         integrity.get("anchor_mode", "-"), "yes" if chain.get("intact") else "no"],
    ], widths=[26 * mm, 22 * mm, 20 * mm, 20 * mm, 22 * mm, 32 * mm, 22 * mm]))
    story.append(Paragraph(
        "The blockchain layer provides tamper-evident integrity for selected security events. Only event hashes and "
        "non-sensitive metadata are anchored; raw traffic remains off-chain. Entries marked as tamper demonstrations "
        "are intentionally altered so that verification failures can be shown during assessment.", small))
    if integrity.get("tamper_demo_events"):
        story.append(Paragraph(
            f"Tamper demonstration entries present: {integrity['tamper_demo_events']} (expected to FAIL verification).", small))

    # --- top entities -----------------------------------------------------
    story.append(Paragraph("9. Most active sources and targets", h2))
    entities = data.get("top_entities") or {}
    if entities.get("sources"):
        rows = [["Source IP", "Flows", "Attack verdicts", "Mean risk"]] + [
            [e["ip"], e["flows"], e["attacks"], round(e["risk"] * 100, 1)] for e in entities["sources"][:6]
        ]
        story.append(_table(rows, widths=[50 * mm, 26 * mm, 36 * mm, 26 * mm]))
    if entities.get("targets"):
        rows = [["Target IP", "Flows", "Attack verdicts", "Mean risk"]] + [
            [e["ip"], e["flows"], e["attacks"], round(e["risk"] * 100, 1)] for e in entities["targets"][:6]
        ]
        story.append(Spacer(1, 4))
        story.append(_table(rows, widths=[50 * mm, 26 * mm, 36 * mm, 26 * mm]))

    story.append(Spacer(1, 10))
    story.append(Paragraph(
        "Generated by CyberForecast AI - AI-Based Network Attack Forecasting & Blockchain-Assured Cybersecurity. "
        "Smart India Hackathon (Blockchain & Cybersecurity theme).", centered))

    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return buffer.getvalue()


def render_csv(data: Dict[str, Any]) -> str:
    """Machine-readable export of the same report contents."""
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    overview = data["overview"]
    kpis = overview.get("kpis", {})
    writer.writerow(["CyberForecast AI - security report"])
    writer.writerow(["generated_at", data["generated_at"]])
    writer.writerow(["window", data["window"]])
    writer.writerow([])
    writer.writerow(["section", "key", "value"])
    for key, value in kpis.items():
        writer.writerow(["kpi", key, value])
    for item in overview.get("attack_distribution") or []:
        writer.writerow(["attack_distribution", item["name"], item["value"]])
    for key, value in (data["alerts"].get("by_severity") or {}).items():
        writer.writerow(["alerts_by_severity", key, value])
    for key, value in (data["blockchain"] or {}).items():
        if not isinstance(value, (dict, list)):
            writer.writerow(["blockchain", key, value])
    for alert in (data.get("critical_alerts") or []) + (data.get("high_alerts") or []):
        writer.writerow(["alert", alert.get("alert_code"),
                         f"{alert.get('timestamp')}|{alert.get('severity')}|{alert.get('attack_type')}|"
                         f"{alert.get('risk_score')}|{alert.get('status')}|{alert.get('source_ip')}"])
    forecast = data.get("forecast") or {}
    for horizon in forecast.get("horizons") or []:
        for category in horizon.get("categories") or []:
            writer.writerow(["forecast", f"{horizon['horizon_minutes']}m|{category['attack_type']}",
                             f"p={category['probability']}|risk={category['risk_level']}|expected={category['expected_events']}"])
    classifier = (data.get("model_registry") or {}).get("active_classifier") or {}
    for key in ("name", "algorithm", "version", "accuracy", "precision_score", "recall_score", "f1_score", "roc_auc", "training_rows"):
        writer.writerow(["model", key, classifier.get(key)])
    for point in (data.get("trends") or {}).get("attacks_over_time") or []:
        writer.writerow(["trend", point["time"], f"attacks={point['attacks']}|flows={point['flows']}"])
    return buffer.getvalue()


def generate(report_type: str = "security_summary", window: str = "24h",
             fmt: str = "pdf", title: Optional[str] = None,
             user: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    fmt = (fmt or "pdf").lower()
    if fmt not in ("pdf", "csv"):
        raise ReportError("Report format must be 'pdf' or 'csv'.")

    data = build_report_data(window, report_type)
    title = title or f"Security Report - {window} window"
    content = render_pdf(data, title) if fmt == "pdf" else render_csv(data).encode("utf-8")

    report_id = new_id()
    filename = f"cyberforecast-report-{report_id}.{fmt}"
    directory = get_reports_dir()
    path = os.path.join(directory, filename)
    with open(path, "wb") as handle:
        handle.write(content)

    summary = {
        "window": window,
        "threat_level": data["overview"].get("threat_level"),
        "kpis": data["overview"].get("kpis"),
        "alerts": data["alerts"],
        "blockchain": {k: v for k, v in data["blockchain"].items() if not isinstance(v, dict)},
        "model": {
            "engine": data["model_registry"].get("inference_engine"),
            "active_classifier": (data["model_registry"].get("active_classifier") or {}).get("name"),
            "accuracy": (data["model_registry"].get("active_classifier") or {}).get("accuracy"),
        },
        "forecast_overall": (data.get("forecast") or {}).get("overall"),
    }
    sections = ["executive_summary", "kpis", "attack_summary", "traffic_trend", "forecast",
                "critical_alerts", "model_performance", "blockchain_integrity", "top_entities"]

    record = get_store().create("reports", {
        "id": report_id,
        "title": title,
        "report_type": report_type,
        "created_at": utcnow(),
        "created_by": (user or {}).get("email", "system"),
        "format": fmt,
        "range": {"window": window},
        "summary": summary,
        "sections": sections,
        "file_path": path,
        "size_bytes": len(content),
    })

    try:
        ledger.record_event(
            event_type="report_generated",
            payload={"report_id": report_id, "title": title, "window": window, "format": fmt,
                     "threat_level": summary["threat_level"], "kpis": summary["kpis"]},
            related_id=report_id,
            recorded_by=(user or {}).get("email", "system"),
        )
    except Exception:  # pragma: no cover
        logger.warning("ledger write failed for report %s", report_id)

    record["data"] = data
    return record


def list_reports(limit: int = 25, offset: int = 0) -> Tuple[List[Dict[str, Any]], int]:
    return get_store().list("reports", order_by="-created_at", limit=limit, offset=offset)


def get_report(report_id: str) -> Optional[Dict[str, Any]]:
    return get_store().get("reports", report_id)


def read_report_file(record: Dict[str, Any]) -> Optional[bytes]:
    path = record.get("file_path")
    if path and os.path.isfile(path):
        with open(path, "rb") as handle:
            return handle.read()
    # Regenerate on demand if the file was lost (ephemeral serverless disks).
    data = build_report_data((record.get("range") or {}).get("window", "24h"), record.get("report_type"))
    if record.get("format") == "csv":
        return render_csv(data).encode("utf-8")
    return render_pdf(data, record.get("title") or "Security Report")


def delete_report(report_id: str) -> bool:
    record = get_report(report_id)
    if not record:
        return False
    path = record.get("file_path")
    if path and os.path.isfile(path):
        try:
            os.remove(path)
        except OSError:
            pass
    return get_store().delete("reports", report_id)
