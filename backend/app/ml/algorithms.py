"""Model catalogue: every algorithm the platform can actually train and serve."""

from __future__ import annotations

from typing import Any, Callable, Dict

from sklearn.ensemble import (
    ExtraTreesClassifier,
    GradientBoostingClassifier,
    HistGradientBoostingClassifier,
    IsolationForest,
    RandomForestClassifier,
)
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier

ALGORITHMS: Dict[str, Dict[str, Any]] = {
    "random_forest": {
        "label": "Random Forest",
        "task": "classification",
        "description": "Bagged decision trees. Robust default for heterogeneous flow features.",
        "factory": lambda: RandomForestClassifier(
            n_estimators=160, max_depth=18, min_samples_split=3, class_weight="balanced_subsample",
            random_state=42, n_jobs=-1,
        ),
        "supports_proba": True,
        "native_importance": True,
    },
    "gradient_boosting": {
        "label": "Gradient Boosting (hist)",
        "task": "classification",
        "description": "Histogram-based gradient boosting. Best accuracy on larger datasets.",
        "factory": lambda: HistGradientBoostingClassifier(
            max_iter=220, learning_rate=0.09, max_depth=None, min_samples_leaf=12,
            l2_regularization=1.0, random_state=42,
        ),
        "supports_proba": True,
        "native_importance": False,
    },
    "logistic_regression": {
        "label": "Logistic Regression",
        "task": "classification",
        "description": "Linear multinomial model. Fast, fully interpretable coefficients.",
        "factory": lambda: LogisticRegression(max_iter=2000, class_weight="balanced", C=1.0),
        "supports_proba": True,
        "native_importance": True,
    },
    "extra_trees": {
        "label": "Extra Trees",
        "task": "classification",
        "description": "Extremely randomized trees. Lower variance than Random Forest.",
        "factory": lambda: ExtraTreesClassifier(
            n_estimators=180, max_depth=18, class_weight="balanced_subsample", random_state=42, n_jobs=-1,
        ),
        "supports_proba": True,
        "native_importance": True,
    },
    "decision_tree": {
        "label": "Decision Tree",
        "task": "classification",
        "description": "Single shallow tree. Useful as an interpretable baseline.",
        "factory": lambda: DecisionTreeClassifier(max_depth=10, min_samples_leaf=8, random_state=42),
        "supports_proba": True,
        "native_importance": True,
    },
    "isolation_forest": {
        "label": "Isolation Forest",
        "task": "anomaly",
        "description": "Unsupervised anomaly detector - flags deviations without needing attack labels.",
        "factory": lambda: IsolationForest(n_estimators=160, contamination="auto", random_state=42, n_jobs=-1),
        "supports_proba": False,
        "native_importance": False,
    },
}


def get_algorithm(name: str) -> Dict[str, Any]:
    key = (name or "random_forest").strip().lower().replace(" ", "_").replace("-", "_")
    aliases = {
        "rf": "random_forest", "randomforest": "random_forest",
        "gbm": "gradient_boosting", "gb": "gradient_boosting", "gradientboosting": "gradient_boosting",
        "lr": "logistic_regression", "logistic": "logistic_regression", "logreg": "logistic_regression",
        "extratrees": "extra_trees", "et": "extra_trees",
        "tree": "decision_tree", "dt": "decision_tree",
        "iforest": "isolation_forest", "isolationforest": "isolation_forest",
    }
    key = aliases.get(key, key)
    if key not in ALGORITHMS:
        raise ValueError(f"Unknown algorithm '{name}'. Available: {', '.join(sorted(ALGORITHMS))}")
    return {**ALGORITHMS[key], "key": key}


def catalogue(task: str | None = None) -> list:
    return [
        {
            "key": key,
            "label": spec["label"],
            "task": spec["task"],
            "description": spec["description"],
            "supports_proba": spec["supports_proba"],
        }
        for key, spec in ALGORITHMS.items()
        if task is None or spec["task"] == task
    ]
