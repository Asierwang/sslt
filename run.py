import os
import sys
from main import SSHClientApp
from PyQt5.QtWidgets import QApplication

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = SSHClientApp()
    window.show()
    sys.exit(app.exec_())