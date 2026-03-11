"""
Advanced YAML rule editor tab.
Allows modifying the engine's YAML rules directly from the GUI.
"""

from __future__ import annotations

import os

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont, QColor, QSyntaxHighlighter, QTextCharFormat
from PySide6.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from utils.logger import get_logger

logger = get_logger(__name__)


class YamlHighlighter(QSyntaxHighlighter):
    """Simple syntax highlighter for YAML."""

    def __init__(self, document):
        super().__init__(document)
        self.key_format = QTextCharFormat()
        self.key_format.setForeground(QColor("#7c3aed"))  # Purple
        self.key_format.setFontWeight(QFont.Bold)

        self.value_format = QTextCharFormat()
        self.value_format.setForeground(QColor("#a0aec0"))  # Grey

        self.comment_format = QTextCharFormat()
        self.comment_format.setForeground(QColor("#4a5568"))  # Dark grey
        self.comment_format.setFontItalic(True)

    def highlightBlock(self, text: str) -> None:
        if text.strip().startswith("#"):
            self.setFormat(0, len(text), self.comment_format)
            return

        if ":" in text:
            parts = text.split(":", 1)
            key_len = len(parts[0]) + 1
            self.setFormat(0, key_len, self.key_format)
            self.setFormat(key_len, len(text) - key_len, self.value_format)
        else:
            self.setFormat(0, len(text), self.value_format)


class RuleEditorTab(QWidget):
    """GUI tab for editing, validating, and reloading YAML rules."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._rules_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rules")
        self._current_file: str | None = None
        self._setup_ui()
        self._load_files()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)

        # Header: File selector
        header_layout = QHBoxLayout()
        title = QLabel("📝 Advanced Rule Editor (YAML)")
        title.setObjectName("sectionTitle")
        
        self._file_combo = QComboBox()
        self._file_combo.setMinimumWidth(250)
        self._file_combo.currentTextChanged.connect(self._on_file_selected)

        btn_new = QPushButton("📄 New")
        btn_new.clicked.connect(self._new_file)

        header_layout.addWidget(title)
        header_layout.addStretch()
        header_layout.addWidget(QLabel("File:"))
        header_layout.addWidget(self._file_combo)
        header_layout.addWidget(btn_new)
        layout.addLayout(header_layout)

        # Editor
        self._editor = QPlainTextEdit()
        font = QFont("Consolas", 10)
        font.setStyleHint(QFont.Monospace)
        self._editor.setFont(font)
        self._editor.setLineWrapMode(QPlainTextEdit.NoWrap)
        self._highlighter = YamlHighlighter(self._editor.document())
        layout.addWidget(self._editor)

        # Footer commands
        footer_layout = QHBoxLayout()
        self._status_label = QLabel("")
        
        btn_save = QPushButton("💾 Save")
        btn_save.clicked.connect(self._save_file)
        btn_save.setStyleSheet("font-weight: bold; color: #10b981;")

        btn_reload = QPushButton("🔄 Force Engine Reload")
        btn_reload.clicked.connect(self._trigger_reload)

        footer_layout.addWidget(self._status_label)
        footer_layout.addStretch()
        footer_layout.addWidget(btn_reload)
        footer_layout.addWidget(btn_save)
        layout.addLayout(footer_layout)

    def _load_files(self) -> None:
        self._file_combo.clear()
        if not os.path.exists(self._rules_dir):
            os.makedirs(self._rules_dir, exist_ok=True)
        
        files = [f for f in os.listdir(self._rules_dir) if f.endswith(".yaml") or f.endswith(".yml")]
        if not files:
            # Create a default
            default_path = os.path.join(self._rules_dir, "custom.yaml")
            with open(default_path, "w") as f:
                f.write("rules:\n  - id: my-custom-rule\n    action: alert\n")
            files = ["custom.yaml"]

        self._file_combo.addItems(sorted(files))

    def _on_file_selected(self, filename: str) -> None:
        if not filename:
            return
        path = os.path.join(self._rules_dir, filename)
        self._current_file = path
        try:
            with open(path, "r", encoding="utf-8") as f:
                self._editor.setPlainText(f.read())
            self._status_label.setText(f"Loaded {filename}")
        except Exception as exc:
            logger.error("Failed to load rule file: %s", exc)
            self._status_label.setText("Error loading file")

    def _save_file(self) -> None:
        if not self._current_file:
            return
        content = self._editor.toPlainText()
        
        # Basic validation
        try:
            import yaml
            yaml.safe_load(content)
        except Exception as exc:
            QMessageBox.warning(self, "Invalid YAML", f"Cannot save: Invalid YAML format.\n\n{exc}")
            return

        try:
            with open(self._current_file, "w", encoding="utf-8") as f:
                f.write(content)
            self._status_label.setText("File saved successfully.")
            logger.info("Rule editor saved %s", self._current_file)
        except Exception as exc:
            logger.error("Failed to save rule file: %s", exc)
            QMessageBox.warning(self, "Save Error", f"Could not save file: {exc}")

    def _new_file(self) -> None:
        self._current_file = None
        self._file_combo.setCurrentIndex(-1)
        self._editor.setPlainText("rules:\n  - id: new-rule\n    name: My New Rule\n    description: ...\n    action: alert\n    conditions:\n      - ...\n")
        self._status_label.setText("Unsaved new file")
        # To actually save this, we should prompt for a filename, but for simplicity, default to custom.yaml if they hit save
        self._current_file = os.path.join(self._rules_dir, "custom_rule.yaml")
        if self._file_combo.findText("custom_rule.yaml") == -1:
            self._file_combo.addItem("custom_rule.yaml")
        self._file_combo.setCurrentText("custom_rule.yaml")

    def _trigger_reload(self) -> None:
        """Trigger the engine's rule manager to hot-reload."""
        from core.rule_engine import get_rule_engine
        engine = get_rule_engine()
        reloaded = engine.reload_if_changed(force=True)
        if reloaded:
            QMessageBox.information(self, "Reloaded", f"Successfully reloaded {reloaded} rule definitions.")
        else:
            QMessageBox.information(self, "Reloaded", "Engine checked files, no logic changes detected or no new files.")
