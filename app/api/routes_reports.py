from pathlib import Path

from fastapi import APIRouter

router = APIRouter()

REPORTS_DIR = Path("data/reports")


@router.get("/reports")
def get_reports() -> list[dict]:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    reports = sorted(REPORTS_DIR.glob("*.html"))

    return [
        {
            "filename": report.name,
            "path": str(report),
        }
        for report in reports
    ]
