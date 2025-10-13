#!/usr/bin/env python3
"""
Log Watcher Service - runs in background to monitor logs and update stats
"""

import sys
import os
sys.path.append(os.path.dirname(__file__))

from log_watcher import run_watchers

if __name__ == "__main__":
    run_watchers()
