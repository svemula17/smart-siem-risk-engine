from typing import Dict, List

from app.models.evaluation_result import EvaluationResult


def calculate_evaluation_summary(results: List[EvaluationResult]) -> Dict[str, float]:
    total = len(results)

    if total == 0:
        return {
            "total_alerts": 0,
            "band_accuracy": 0.0,
            "action_accuracy": 0.0,
        }

    correct_band = sum(1 for result in results if result.is_correct_band)
    correct_action = sum(1 for result in results if result.is_correct_action)

    return {
        "total_alerts": total,
        "correct_band_predictions": correct_band,
        "correct_action_predictions": correct_action,
        "band_accuracy": round((correct_band / total) * 100, 2),
        "action_accuracy": round((correct_action / total) * 100, 2),
    }