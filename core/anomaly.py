"""
ML-based anomaly detection using scikit-learn Isolation Forest.

Falls back to threshold-based detection if scikit-learn is not installed.
"""

from __future__ import annotations

import os
import time
from collections import deque
from typing import Any

from utils.logger import get_logger

logger = get_logger(__name__)

try:
    import numpy as np
    from sklearn.ensemble import IsolationForest
    import joblib
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False
    logger.warning("scikit-learn/numpy not installed; using threshold-based anomaly detection.")


class AnomalyDetector:
    """
    Wraps an Isolation Forest model for detecting anomalous connection patterns.

    If scikit-learn is unavailable, falls back to simple threshold comparison.
    """

    def __init__(
        self,
        model_path: str = "anomaly_model.pkl",
        contamination: float = 0.05,
        threshold_fallback: int = 50,
        retrain_interval_seconds: int = 3600,
    ) -> None:
        self.model_path = model_path
        self.contamination = contamination
        self.threshold_fallback = threshold_fallback
        self.retrain_interval = retrain_interval_seconds

        self._model: Any = None
        self._training_data: deque[list[float]] = deque(maxlen=5000)
        self._last_trained: float = 0.0
        self._is_trained: bool = False

        if HAS_SKLEARN:
            self._load_model()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def record(self, ip: str, count: int, ports_hit: list[int]) -> None:
        """Record a data point for future training."""
        if not HAS_SKLEARN:
            return
        self._training_data.append([float(count), float(len(set(ports_hit)))])
        # auto-retrain if interval has passed and we have enough data
        if (
            len(self._training_data) >= 100
            and time.time() - self._last_trained > self.retrain_interval
        ):
            self.train()

    def train(self) -> bool:
        """Train (or retrain) the Isolation Forest model on collected data."""
        if not HAS_SKLEARN:
            return False
        if len(self._training_data) < 20:
            logger.debug("Not enough data to train anomaly model (%d samples).", len(self._training_data))
            return False
        try:
            X = np.array(list(self._training_data))
            model = IsolationForest(contamination=self.contamination, random_state=42)
            model.fit(X)
            self._model = model
            self._is_trained = True
            self._last_trained = time.time()
            self._save_model()
            logger.info("Anomaly model trained on %d samples.", len(self._training_data))
            return True
        except Exception as exc:
            logger.error("Anomaly model training failed: %s", exc)
            return False

    def is_anomaly(self, ip: str, count: int, ports_hit: list[int]) -> bool:
        """
        Return True if the given connection pattern is anomalous.

        Records the data point for future training and checks against the model.
        """
        self.record(ip, count, ports_hit)

        if not HAS_SKLEARN or not self._is_trained or self._model is None:
            # fallback: simple threshold
            return count > self.threshold_fallback

        try:
            X = np.array([[float(count), float(len(set(ports_hit)))]])
            prediction = self._model.predict(X)
            return bool(prediction[0] == -1)
        except Exception as exc:
            logger.error("Anomaly prediction failed: %s", exc)
            return False

    # ------------------------------------------------------------------
    # Model persistence
    # ------------------------------------------------------------------

    def _save_model(self) -> None:
        if not HAS_SKLEARN or self._model is None:
            return
        try:
            joblib.dump(self._model, self.model_path)
            logger.debug("Anomaly model saved to %s", self.model_path)
        except Exception as exc:
            logger.warning("Could not save anomaly model: %s", exc)

    def _load_model(self) -> None:
        if not HAS_SKLEARN:
            return
        if not os.path.exists(self.model_path):
            return
        try:
            self._model = joblib.load(self.model_path)
            self._is_trained = True
            self._last_trained = time.time()
            logger.info("Anomaly model loaded from %s", self.model_path)
        except Exception as exc:
            logger.warning("Could not load anomaly model: %s", exc)
