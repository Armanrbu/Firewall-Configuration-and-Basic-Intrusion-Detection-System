"""
Pytest configuration and shared fixtures.
"""
import sys
import os
import pytest

# Ensure the project root is on the Python path so all modules resolve.
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)


@pytest.fixture(autouse=True, scope="session")
def _clean_stale_model_pkl():
    """
    Remove any stale anomaly_model.pkl from the project root before the test
    session begins.  Prevents the pre-existing 2-feature IsolationForest from
    being loaded by tests that create their own detector with a tmp_path model.
    """
    stale = os.path.join(_ROOT, "anomaly_model.pkl")
    if os.path.exists(stale):
        os.remove(stale)
    yield
