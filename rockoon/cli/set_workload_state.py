#!/usr/bin/env python3

import sys
from rockoon import kube


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("usage: set_workload_state.py <node> <state>")
        sys.exit(0)
    kube.NodeWorkloadLock.get(sys.argv[1]).set_state(sys.argv[2])
