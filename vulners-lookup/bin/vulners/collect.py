import os
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "..", "lib"))

from scanner.scanner import Scanner

SPLUNK_HOME = os.environ.get('SPLUNK_HOME', '')
LOG_PATH = os.path.join(SPLUNK_HOME, 'var', 'log', 'vulners-lookup')

s = Scanner(log_level="DEBUG", log_path=LOG_PATH)
s.run()
