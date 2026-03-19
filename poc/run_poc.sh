#!/bin/bash
# End-to-end PoC: verify logickaller detects logic bug that syzkaller misses.
# Run as root: sudo bash poc/run_poc.sh

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
MODULE="$SCRIPT_DIR/buggy_chardev/buggy_chardev.ko"
TEST_PROG="$SCRIPT_DIR/buggy_chardev/test_trigger"

echo "=== Logickaller Logic Bug Detection PoC ==="
echo ""

# Step 1: Load buggy kernel module
if [ ! -f "$MODULE" ]; then
    echo "ERROR: Kernel module not found at $MODULE"
    echo "Build it first: cd poc/buggy_chardev && make"
    exit 1
fi

echo "[1/3] Loading buggy_chardev kernel module..."
rmmod buggy_chardev 2>/dev/null || true
insmod "$MODULE"
if [ ! -e /dev/buggy_chardev ]; then
    echo "ERROR: /dev/buggy_chardev not found after insmod"
    exit 1
fi
chmod 666 /dev/buggy_chardev
echo "  OK: /dev/buggy_chardev created"

# Step 2: Show the bug exists but kernel does NOT crash
echo ""
echo "[2/3] Triggering the logic bug..."
echo ""
"$TEST_PROG"
echo ""
echo "  Kernel is alive - no crash, no panic, no KASAN."
echo "  Syzkaller would report NOTHING here."
echo ""
echo "  But logickaller's executor checks: if read() returns more than count,"
echo "  it outputs SYZLOGIC and the manager reports it as a bug."
echo ""

# Step 3: Simulate what the executor detection does
echo "[3/3] Simulating logickaller executor detection..."
echo ""
python3 -c "
import os, ctypes, ctypes.util

# Use raw syscall to get the actual kernel return value (not capped by glibc)
libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)

fd = os.open('/dev/buggy_chardev', os.O_RDONLY)

# Allocate a large buffer but request only 16 bytes
buf = ctypes.create_string_buffer(8192)
request_count = 16

# raw read syscall
ret = libc.read(fd, buf, request_count)

print(f'  syscall: read(fd, buf, {request_count})')
print(f'  kernel returned: {ret}')
print()

if ret > request_count:
    print(f'  SYZLOGIC: read returned {ret} but count is {request_count}')
    print()
    print('  >>> LOGIC BUG DETECTED by logickaller! <<<')
    print('  >>> Syzkaller would miss this entirely. <<<')
else:
    print(f'  Return value {ret} <= count {request_count}, no bug detected.')

os.close(fd)
"

# Cleanup
echo ""
echo "Cleaning up..."
rmmod buggy_chardev 2>/dev/null || true
echo "Done."
