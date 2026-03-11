"""
Dark theme stylesheet and colour constants shared across the UI.
"""

DARK_STYLESHEET = """
QWidget {
    background-color: #1e1e2e;
    color: #e2e8f0;
    font-family: "Segoe UI", Arial, sans-serif;
    font-size: 10pt;
}
QMainWindow, QDialog {
    background-color: #1e1e2e;
}
QTabWidget::pane {
    border: 1px solid #3a3a5c;
    background: #2a2a3e;
}
QTabBar::tab {
    background: #2a2a3e;
    color: #a0aec0;
    padding: 8px 16px;
    border-top-left-radius: 6px;
    border-top-right-radius: 6px;
    min-width: 100px;
}
QTabBar::tab:selected {
    background: #7c3aed;
    color: #ffffff;
    font-weight: bold;
}
QTabBar::tab:hover:!selected {
    background: #3a3a5c;
    color: #e2e8f0;
}
QPushButton {
    background-color: #7c3aed;
    color: #ffffff;
    border: none;
    border-radius: 6px;
    padding: 7px 16px;
    font-weight: bold;
}
QPushButton:hover {
    background-color: #6d28d9;
}
QPushButton:pressed {
    background-color: #5b21b6;
}
QPushButton:disabled {
    background-color: #3a3a5c;
    color: #6b7280;
}
QPushButton#dangerBtn {
    background-color: #dc2626;
}
QPushButton#dangerBtn:hover {
    background-color: #b91c1c;
}
QPushButton#successBtn {
    background-color: #16a34a;
}
QPushButton#successBtn:hover {
    background-color: #15803d;
}
QLineEdit, QTextEdit, QPlainTextEdit, QSpinBox, QComboBox {
    background-color: #2a2a3e;
    color: #e2e8f0;
    border: 1px solid #3a3a5c;
    border-radius: 4px;
    padding: 4px 8px;
    selection-background-color: #7c3aed;
}
QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus,
QSpinBox:focus, QComboBox:focus {
    border: 1px solid #7c3aed;
}
QTableWidget {
    background-color: #2a2a3e;
    gridline-color: #3a3a5c;
    border: none;
    selection-background-color: #7c3aed;
    alternate-background-color: #252538;
}
QTableWidget::item {
    padding: 4px;
}
QHeaderView::section {
    background-color: #1e1e2e;
    color: #a0aec0;
    padding: 6px;
    border: none;
    border-bottom: 1px solid #3a3a5c;
    font-weight: bold;
}
QScrollBar:vertical {
    background: #2a2a3e;
    width: 10px;
    border-radius: 5px;
}
QScrollBar::handle:vertical {
    background: #4a4a6e;
    border-radius: 5px;
    min-height: 20px;
}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0;
}
QStatusBar {
    background: #1a1a2e;
    color: #a0aec0;
    border-top: 1px solid #3a3a5c;
}
QGroupBox {
    border: 1px solid #3a3a5c;
    border-radius: 6px;
    margin-top: 12px;
    padding-top: 8px;
    color: #a0aec0;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 4px;
    color: #7c3aed;
    font-weight: bold;
}
QCheckBox::indicator {
    width: 16px;
    height: 16px;
    border: 1px solid #4a4a6e;
    border-radius: 3px;
    background: #2a2a3e;
}
QCheckBox::indicator:checked {
    background: #7c3aed;
    border-color: #7c3aed;
}
QLabel#sectionTitle {
    font-size: 13pt;
    font-weight: bold;
    color: #7c3aed;
}
"""

LIGHT_STYLESHEET = """
QWidget {
    background-color: #f8f9fa;
    color: #1a1a2e;
    font-family: "Segoe UI", Arial, sans-serif;
    font-size: 10pt;
}
QPushButton {
    background-color: #7c3aed;
    color: #ffffff;
    border: none;
    border-radius: 6px;
    padding: 7px 16px;
    font-weight: bold;
}
QPushButton:hover {
    background-color: #6d28d9;
}
QTableWidget {
    background-color: #ffffff;
    gridline-color: #e2e8f0;
    border: 1px solid #e2e8f0;
    alternate-background-color: #f5f3ff;
}
QHeaderView::section {
    background-color: #ede9fe;
    color: #4b5563;
    padding: 6px;
    border: none;
    border-bottom: 1px solid #c4b5fd;
    font-weight: bold;
}
QLineEdit, QTextEdit, QSpinBox, QComboBox {
    background-color: #ffffff;
    border: 1px solid #d1d5db;
    border-radius: 4px;
    padding: 4px 8px;
}
"""


def get_stylesheet(theme: str = "dark") -> str:
    return LIGHT_STYLESHEET if theme == "light" else DARK_STYLESHEET
