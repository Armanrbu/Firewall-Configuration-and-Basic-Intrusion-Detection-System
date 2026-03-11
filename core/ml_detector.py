"""
ML-based anomaly detector implementing AbstractDetector.

Uses PyOD ECOD (Empirical Cumulative Distribution-based Outlier Detection)
when available, falls back to scikit-learn IsolationForest, then falls back
to simple threshold-based detection if neither is installed.

Features:
- Batch scoring: analyze() accepts lists of events
- Auto-retrain: triggered when enough new data is collected
- Persistent model: saved to disk via joblib
- Signature fallback: rule-based when no model is trained

Usage:
    from core.ml_detector import MLAnomalyDetector
    from core.detector_registry import get_registry

    det = MLAnomalyDetector()
    registry = get_registry()
    registry.register(det)
"""

from __future__ import annotations

import os
import threading
import time
from collections import deque
from typing import Any

from utils.logger import get_logger
from core.detector_abc import AbstractDetector, DetectorResult

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Backend detection
# ---------------------------------------------------------------------------

try:
    from pyod.models.ecod import ECOD
    import numpy as np
    import joblib
    HAS_PYOD = True
    logger.debug("PyOD available — ECOD detector active.")
except ImportError:
    HAS_PYOD = False
    logger.debug("PyOD not installed — trying scikit-learn IsolationForest.")

if not HAS_PYOD:
    try:
        import numpy as np
        from sklearn.ensemble import IsolationForest
        import joblib
        HAS_SKLEARN = True
        logger.debug("scikit-learn available — IsolationForest detector active.")
    except ImportError:
        HAS_SKLEARN = False
        logger.warning(
            "Neither PyOD nor scikit-learn installed; ML detector uses threshold fallback. "
            "Run: pip install pyod numpy joblib"
        )
else:
    HAS_SKLEARN = False  # PyOD takes priority


# ---------------------------------------------------------------------------
# Feature extraction
# ---------------------------------------------------------------------------

def extract_features(ip: str, events: list[Any], context: dict[str, Any] | None = None) -> list[float]:
    """Extract numerical features from a list of connection events.

    Features (in order):
        0: connection count
        1: unique ports hit
        2: unique protocols (TCP/UDP/etc.)
        3: inbound ratio (direction == "in")
        4: connections per second (rate)
        5: max port number (normalised /65535)
        6: well-known port hits (port <= 1024)
    """
    ctx = context or {}
    count = len(events)

    ports = [getattr(e, "port", 0) for e in events]
    protocols = [getattr(e, "protocol", "TCP") for e in events]
    directions = [getattr(e, "direction", "in") for e in events]
    timestamps = [getattr(e, "timestamp", 0.0) for e in events]

    unique_ports = len(set(p for p in ports if p))
    unique_protos = len(set(protocols))
    inbound = sum(1 for d in directions if d == "in")
    inbound_ratio = inbound / max(count, 1)

    # Rate: connections per second over the observed window
    if len(timestamps) >= 2:
        span = max(timestamps) - min(timestamps)
        rate = count / max(span, 1.0)
    else:
        rate = 0.0

    max_port = max(ports) if ports else 0
    max_port_norm = max_port / 65535.0

    well_known_hits = sum(1 for p in ports if 0 < p <= 1024)

    return [
        float(count),
        float(unique_ports),
        float(unique_protos),
        float(inbound_ratio),
        float(rate),
        float(max_port_norm),
        float(well_known_hits),
    ]


FEATURE_NAMES = [
    "count", "unique_ports", "unique_protocols", "inbound_ratio",
    "rate_per_second", "max_port_norm", "well_known_port_hits",
]


# ---------------------------------------------------------------------------
# Signature fallback rules
# ---------------------------------------------------------------------------

def signature_check(features: list[float]) -> tuple[bool, str]:
    """Simple rule-based detection when no model is available.

    Returns (is_anomaly, reason).
    """
    count = features[0]
    unique_ports = features[1]
    rate = features[4]
    well_known = features[6]

    if count >= 100:
        return True, f"Very high connection count: {count:.0f}"
    if unique_ports >= 20:
        return True, f"Wide port scan: {unique_ports:.0f} distinct ports"
    if rate >= 10:
        return True, f"High connection rate: {rate:.1f}/s"
    if well_known >= 10 and unique_ports >= 8:
        return True, f"Multi-service probe: {well_known:.0f} well-known port hits"
    return False, ""


# ---------------------------------------------------------------------------
# MLAnomalyDetector
# ---------------------------------------------------------------------------

class MLAnomalyDetector(AbstractDetector):
    """
    Anomaly detector using PyOD ECOD → IsolationForest → threshold fallback.

    Implements the AbstractDetector interface so it can be registered
    in the DetectorRegistry alongside rule-based detectors.
    """

    name = "ml_anomaly"
    version = "2.0.0"

    def __init__(
        self,
        model_path: str = "anomaly_model.pkl",
        contamination: float = 0.05,
        threshold_fallback: int = 50,
        retrain_interval_seconds: int = 3600,
        min_train_samples: int = 50,
        batch_size: int = 32,
    ) -> None:
        self.model_path = model_path
        self.contamination = contamination
        self.threshold_fallback = threshold_fallback
        self.retrain_interval = retrain_interval_seconds
        self.min_train_samples = min_train_samples
        self.batch_size = batch_size

        self._model: Any = None
        self._training_buffer: deque[list[float]] = deque(maxlen=10_000)
        self._last_trained: float = 0.0
        self._is_trained: bool = False
        self._lock = threading.RLock()

        self._load_model()

    # ------------------------------------------------------------------
    # AbstractDetector interface
    # ------------------------------------------------------------------

    def on_start(self) -> None:
        logger.info("MLAnomalyDetector started (backend=%s)", self._backend_name())

    def on_stop(self) -> None:
        if len(self._training_buffer) >= self.min_train_samples:
            logger.info("MLAnomalyDetector stopping — saving training buffer state.")

    def on_train(self, data: list[Any]) -> None:
        """Trigger training from external data (called by registry.train_all)."""
        self.train()

    def analyze(
        self,
        ip: str,
        events: list[Any],
        *,
        context: dict[str, Any] | None = None,
    ) -> DetectorResult:
        """Score the event list for anomalies.

        Records features for future training and uses the current model
        (or signature fallback) to determine if the behaviour is anomalous.
        """
        if not events:
            return DetectorResult(triggered=False, score=0.0)

        features = extract_features(ip, events, context)
        self._record(features)
        self._maybe_retrain()

        with self._lock:
            is_anomaly, score, reason = self._score(features)

        if not is_anomaly:
            return DetectorResult(
                triggered=False,
                score=score,
                features=dict(zip(FEATURE_NAMES, features)),
            )

        return DetectorResult(
            triggered=True,
            score=score,
            reason=reason,
            features=dict(zip(FEATURE_NAMES, features)),
            rule_id=f"ml_anomaly_{self._backend_name()}",
            action="block" if score >= 0.85 else "alert",
        )

    # ------------------------------------------------------------------
    # Scoring
    # ------------------------------------------------------------------

    def _score(self, features: list[float]) -> tuple[bool, float, str]:
        """Return (is_anomaly, confidence_score, reason)."""
        if not (HAS_PYOD or HAS_SKLEARN) or not self._is_trained or self._model is None:
            # signature fallback
            sig_anomaly, sig_reason = signature_check(features)
            sig_score = 0.6 if sig_anomaly else 0.0
            return sig_anomaly, sig_score, sig_reason or "signature check"

        try:
            X = [features]
            if HAS_PYOD:
                score_raw = float(self._model.decision_function(X)[0])
                # ECOD: higher score = more anomalous; normalise to 0-1
                # decision_function returns raw score; predict gives -1/1
                label = int(self._model.predict(X)[0])
                is_anom = (label == 1)
                norm_score = min(1.0, max(0.0, (score_raw + 10) / 20))
                reason = f"ECOD anomaly score: {score_raw:.3f}"
            else:
                # IsolationForest: predict() returns -1 for outlier
                label = int(self._model.predict(X)[0])
                raw = float(self._model.decision_function(X)[0])
                is_anom = (label == -1)
                # Convert IF score (higher = more normal) to 0-1 anomaly score
                norm_score = min(1.0, max(0.0, 0.5 - raw))
                reason = f"IsolationForest anomaly score: {raw:.3f}"

            return is_anom, norm_score if is_anom else 0.0, reason

        except Exception as exc:
            logger.error("ML scoring failed: %s", exc)
            sig_anomaly, sig_reason = signature_check(features)
            return sig_anomaly, 0.5 if sig_anomaly else 0.0, sig_reason

    # ------------------------------------------------------------------
    # Training
    # ------------------------------------------------------------------

    def _record(self, features: list[float]) -> None:
        with self._lock:
            self._training_buffer.append(features)

    def _maybe_retrain(self) -> None:
        with self._lock:
            enough_data = len(self._training_buffer) >= self.min_train_samples
            interval_passed = time.time() - self._last_trained > self.retrain_interval

        if enough_data and interval_passed:
            # Train on a background thread so analyze() doesn't block
            threading.Thread(target=self.train, daemon=True, name="ml-retrain").start()

    def train(self) -> bool:
        """Train or retrain the ML model. Returns True on success."""
        if not (HAS_PYOD or HAS_SKLEARN):
            logger.debug("ML libraries not installed — skipping train().")
            return False

        with self._lock:
            if len(self._training_buffer) < self.min_train_samples:
                logger.debug(
                    "Not enough samples to train (%d < %d).",
                    len(self._training_buffer), self.min_train_samples,
                )
                return False
            data = list(self._training_buffer)

        try:
            import numpy as np
            X = np.array(data)

            if HAS_PYOD:
                model = ECOD(contamination=self.contamination)
                model.fit(X)
            else:
                model = IsolationForest(
                    contamination=self.contamination,
                    random_state=42,
                    n_estimators=100,
                )
                model.fit(X)

            with self._lock:
                self._model = model
                self._is_trained = True
                self._last_trained = time.time()

            self._save_model()
            logger.info(
                "MLAnomalyDetector trained on %d samples (backend=%s).",
                len(data), self._backend_name(),
            )
            return True
        except Exception as exc:
            logger.error("ML training failed: %s", exc)
            return False

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _save_model(self) -> None:
        try:
            import joblib
            joblib.dump(self._model, self.model_path)
            logger.debug("Model saved to %s", self.model_path)
        except Exception as exc:
            logger.warning("Could not save model: %s", exc)

    def _load_model(self) -> None:
        if not (HAS_PYOD or HAS_SKLEARN):
            return
        if not os.path.exists(self.model_path):
            return
        try:
            import joblib
            self._model = joblib.load(self.model_path)
            self._is_trained = True
            self._last_trained = time.time()
            logger.info("Model loaded from %s", self.model_path)
        except Exception as exc:
            logger.warning("Could not load model: %s", exc)

    def _backend_name(self) -> str:
        if HAS_PYOD:
            return "pyod-ecod"
        if HAS_SKLEARN:
            return "sklearn-isolation-forest"
        return "signature-fallback"

    # ------------------------------------------------------------------
    # Diagnostics
    # ------------------------------------------------------------------

    def get_info(self) -> dict[str, Any]:
        """Return diagnostic info for API/CLI use."""
        with self._lock:
            return {
                "backend": self._backend_name(),
                "is_trained": self._is_trained,
                "training_samples": len(self._training_buffer),
                "last_trained": self._last_trained,
                "model_path": self.model_path,
                "features": FEATURE_NAMES,
            }
