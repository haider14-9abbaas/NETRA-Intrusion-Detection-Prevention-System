# services/anomaly_ml.py
from __future__ import annotations

import pandas as pd

def add_anomaly_scores(df: pd.DataFrame, contamination: float = 0.08) -> pd.DataFrame:
    """
    Adds:
      - anomaly_score (float)
      - is_anomaly (bool)
    Uses IsolationForest on numeric fields.
    """
    df = df.copy()
    if df.empty:
        df["anomaly_score"] = 0.0
        df["is_anomaly"] = False
        return df

    try:
        from sklearn.ensemble import IsolationForest
    except Exception:
        df["anomaly_score"] = 0.0
        df["is_anomaly"] = False
        return df

    features = ["failed_logins", "ports_scanned", "cpu_percent", "traffic_mbps"]
    for c in features:
        if c not in df.columns:
            df[c] = 0

    X = df[features].fillna(0)

    model = IsolationForest(
        n_estimators=200,
        contamination=float(contamination),
        random_state=42,
    )
    model.fit(X)

    # decision_function: higher = more normal
    scores = model.decision_function(X)
    preds = model.predict(X)  # -1 anomaly, 1 normal

    df["anomaly_score"] = scores.astype(float)
    df["is_anomaly"] = (preds == -1)
    return df
