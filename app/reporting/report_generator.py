from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from app.models.evaluation_result import EvaluationResult
from app.models.normalized_alert import NormalizedAlert
from app.models.raw_alert import RawAlert
from app.models.scored_alert import ScoredAlert

TEMPLATES_DIR = Path("app/reporting/templates")
REPORTS_DIR = Path("data/reports")

env = Environment(loader=FileSystemLoader(TEMPLATES_DIR))


def generate_incident_report(
    raw_alert: RawAlert,
    normalized_alert: NormalizedAlert,
    scored_alert: ScoredAlert,
    evaluation: EvaluationResult,
) -> str:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    template = env.get_template("incident_report.html")
    html_content = template.render(
        raw_alert=raw_alert,
        normalized_alert=normalized_alert,
        scored_alert=scored_alert,
        evaluation=evaluation,
    )

    output_file = REPORTS_DIR / f"incident_{raw_alert.id}.html"
    output_file.write_text(html_content, encoding="utf-8")

    return str(output_file)


def generate_evaluation_summary_report(
    results: list[EvaluationResult],
    summary: dict,
) -> str:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    template = env.get_template("evaluation_report.html")
    html_content = template.render(
        results=results,
        summary=summary,
    )

    output_file = REPORTS_DIR / "evaluation_summary.html"
    output_file.write_text(html_content, encoding="utf-8")

    return str(output_file)
