"""Forensic workbench visual theme."""

APP_STYLE = r"""
* {
    font-family: "Segoe UI", "Inter", sans-serif;
    font-size: 13px;
    color: #dce7ed;
}
QMainWindow, QWidget#Root { background: #081118; }
QFrame#TopBar {
    background: #0d1a23;
    border-bottom: 1px solid #233542;
}
QLabel#Brand { font-size: 21px; font-weight: 700; color: #f4fbff; }
QLabel#BrandMark {
    font-size: 18px; font-weight: 800; color: #071116;
    background: #55d3c2; border-radius: 8px; padding: 8px;
}
QLabel#Muted, QLabel.muted { color: #8298a5; }
QLabel#PageTitle { font-size: 22px; font-weight: 700; color: #f4fbff; }
QLabel#SectionTitle { font-size: 15px; font-weight: 650; color: #edf7fb; }
QLabel#MetricValue { font-size: 28px; font-weight: 750; color: #f4fbff; }
QLabel#MetricLabel { font-size: 11px; font-weight: 600; color: #8ca3af; }
QLabel#MetricAccent { color: #55d3c2; }
QFrame#Sidebar { background: #0b171f; border-right: 1px solid #20313c; }
QListWidget#Navigation {
    background: transparent; border: 0; outline: none; padding: 10px 8px;
}
QListWidget#Navigation::item {
    color: #92a8b4; padding: 12px 14px; margin: 3px 0; border-radius: 7px;
}
QListWidget#Navigation::item:hover { background: #132631; color: #e8f4f8; }
QListWidget#Navigation::item:selected {
    background: #15333b; color: #67dfcf; border-left: 3px solid #55d3c2;
}
QFrame#Card, QGroupBox {
    background: #0e1c25; border: 1px solid #243843; border-radius: 10px;
}
QGroupBox { margin-top: 12px; padding: 14px; font-weight: 650; }
QGroupBox::title { subcontrol-origin: margin; left: 12px; padding: 0 5px; color: #bcd0d9; }
QPushButton {
    background: #18303b; border: 1px solid #2b4653; border-radius: 7px;
    padding: 8px 13px; color: #dce9ee; font-weight: 600;
}
QPushButton:hover { background: #21414d; border-color: #417080; }
QPushButton:pressed { background: #112932; }
QPushButton:disabled { color: #536771; background: #111e25; border-color: #1d2a31; }
QPushButton#Primary { background: #2b9f93; border-color: #47c6b7; color: #04100f; }
QPushButton#Primary:hover { background: #4fc8b9; }
QPushButton#Danger { background: #4a2627; border-color: #74393a; color: #ffcbcb; }
QLineEdit, QTextEdit, QTextBrowser, QComboBox {
    background: #09141b; border: 1px solid #2a3e49; border-radius: 7px;
    padding: 8px; selection-background-color: #2b9f93;
}
QLineEdit:focus, QTextEdit:focus, QComboBox:focus { border-color: #45bfb1; }
QComboBox::drop-down { border: 0; width: 24px; }
QTableWidget {
    background: #0a151c; alternate-background-color: #0d1c24; border: 1px solid #243743;
    border-radius: 8px; gridline-color: #1c2d37; selection-background-color: #17434a;
}
QHeaderView::section {
    background: #122630; color: #aac0ca; padding: 9px; border: 0;
    border-right: 1px solid #263b46; font-weight: 650;
}
QTableWidget::item { padding: 6px; }
QScrollBar:vertical { background: #0a151c; width: 11px; margin: 0; }
QScrollBar::handle:vertical { background: #314852; min-height: 28px; border-radius: 5px; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QCheckBox { spacing: 7px; color: #a8bbc4; }
QStatusBar { background: #0b171f; color: #78909b; border-top: 1px solid #1d303a; }
QToolTip { background: #172a34; color: white; border: 1px solid #35505d; padding: 5px; }
"""

