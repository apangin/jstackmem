#!/usr/bin/python
import bisect
import re
import subprocess
import sys

if len(sys.argv) < 2:
    print("Calculate stack memory used by a Java process")
    print("Usage: python jstackmem.py <pid>")
    sys.exit()

# Read memory map of the target process
try:
    pid = sys.argv[1]
    with open("/proc/" + pid + "/smaps") as f:
        smaps = f.readlines()
except Exception as e:
    print("Failed to open process memory map")
    print(e)
    sys.exit()

# Parse memory map
last_addr = None
addr = []
pss = []
shared = []
for line in smaps:
    m = re.match("([0-9a-f]+)-([0-9a-f]+) (..).+", line)
    if m:
        last_addr = int(m.group(1), 16) if m.group(3) == "rw" else None
    elif last_addr:
        m = re.match("Pss: +([0-9]+) kB", line)
        if m:
            addr.append(last_addr)
            pss.append(int(m.group(1)))
            shared.append(False)

# Match stack addresses from jstack output with the memory map
try:
    stack_total = 0
    jstack = subprocess.Popen(["jstack", pid], stdout=subprocess.PIPE)
    while True:
        line = jstack.stdout.readline()
        if not line:
            break
        m = re.match("\"([^\"]*)\" .+\[0x([0-9a-f]+)\]\n", line)
        if m:
            addr_index = bisect.bisect(addr, int(m.group(2), 16)) - 1
            if shared[addr_index]:
                # Region already counted
                print("%6d` %s" % (pss[addr_index], m.group(1)))
            else:
                print("%6d  %s" % (pss[addr_index], m.group(1)))
                stack_total += pss[addr_index]
                shared[addr_index] = True
except Exception as e:
    print("Failed to execute jstack")
    print(e)
    sys.exit()

print("%6d  (Total)" % stack_total)
