# Logickaller: Logic Bug Detection PoC

## Bug Description

This PoC demonstrates a class of **kernel I/O return value semantic bugs**.

A buggy kernel driver's `read()` implementation ignores the user-supplied `count`
argument and returns more bytes than requested. This leads to:

- **Information leaks**: the kernel copies out-of-bounds kernel stack/heap data
  into userspace beyond what was requested.
- **Userspace buffer overflows**: the caller allocates a buffer sized to `count`,
  but the kernel writes far more data into it.

Crucially, **the kernel does not crash**. There is no panic, no KASAN report,
no WARN, no BUG_ON, no abnormal log output. The kernel continues running normally.

### Real-World Examples

| CVE / Reference | Description |
|---|---|
| CVE-2020-14386 | `af_packet`: `tpacket_rcv()` miscalculates packet size, out-of-bounds access |
| CVE-2017-18344 | `timer_create` fails to validate fields, leaking kernel memory |
| Various `/proc/*` fixes | Incorrect `copy_to_user` return value handling in procfs readers |
| `splice()`/`sendfile()` fixes | Incorrect byte count on partial I/O completion |

### PoC Bug

`buggy_chardev/buggy_chardev.c` is a minimal kernel char device module whose
`read()` always copies 4096 bytes and returns 4096, regardless of the requested
count:

```c
static ssize_t buggy_read(struct file *file, char __user *buf,
                          size_t count, loff_t *ppos)
{
    size_t to_copy = BUF_SIZE;  // always 4096, ignores count

    if (copy_to_user(buf, internal_buf, to_copy))
        return -EFAULT;

    return to_copy;  // BUG: should return min(count, to_copy)
}
```

When userspace calls `read(fd, buf, 16)`, the kernel returns 4096 instead of 16.

## Why Syzkaller Cannot Detect This

Syzkaller's bug detection relies entirely on **kernel-side error reporting**:

| Mechanism | What it catches |
|---|---|
| Kernel panic / oops | Memory corruption, null derefs |
| KASAN | Out-of-bounds access, use-after-free |
| KMSAN | Uninitialized memory usage |
| LOCKDEP | Lock ordering violations |
| `BUG_ON` / `WARN_ON` | Explicit kernel assertions |

When `read()` returns a wrong positive integer (e.g., 4096 instead of 16):

- The kernel does not crash — no panic is triggered.
- No out-of-bounds kernel memory access occurs — KASAN stays silent.
- No lock issues — LOCKDEP is not involved.
- No kernel log output of any kind.

**Syzkaller executes `read()`, sees the kernel is still alive, and moves on.
It never inspects the return value for semantic correctness.**

## How Logickaller Detects This

Logickaller adds a **return value oracle** in the executor. After every I/O
syscall (`read`, `write`, `pread64`, `pwrite64`, `recv`, `send`, `recvfrom`,
`sendto`), it checks:

```
if (return_value > 0  &&  return_value > count_argument)  →  report SYZLOGIC bug
```

This enforces a **POSIX invariant**: an I/O syscall must never return more bytes
than requested. Any violation is necessarily a kernel bug.

When the check fires, the executor:

1. Writes `SYZLOGIC: <syscall> returned <ret> but count is <count>` to stderr
   (captured by the runner process).
2. Writes the same message to `/dev/kmsg` (kernel log), which appears on the
   VM serial console.

The VM console monitor (`monitorExecution`) detects the `SYZLOGIC:` pattern
via `ContainsCrash()`, and the standard crash pipeline saves it to disk and
displays it in the web UI — exactly like any kernel crash.

### Crash Pipeline Integration

During fuzzing with VMs, the detection flows through the existing crash pipeline:

```
executor: fprintf(stderr, "SYZLOGIC: ...")      → captured as ExecResult.output
executor: write(/dev/kmsg, "SYZLOGIC: ...")      → appears in kernel log
    ↓
VM serial console output
    ↓
vm.go: monitorExecution() → reporter.ContainsCrash()
    ↓
reporter.Parse() → *report.Report{Title: "SYZLOGIC: ..."}
    ↓
manager.go: mgr.crashes <- &Crash{Report: rep}
    ↓
CrashStore.SaveCrash() → workdir/crashes/{hash}/
    ↓
Web UI: /crash?id={hash}
```

No additional plumbing is needed. The `SYZLOGIC:` pattern is treated identically
to `KASAN:`, `BUG:`, or any other kernel crash pattern.

## Reproducing on a Local Machine (No VM Required)

### Prerequisites

- Linux system with `sudo` access
- Kernel headers installed (`linux-headers-$(uname -r)`)
- `gcc`, `make`, `python3`, Go toolchain

### Step 1: Build Everything

```bash
cd /home1/maoyi/logickaller

# Build logickaller executor (with return value oracle)
make executor

# Build the buggy kernel module
cd poc/buggy_chardev && make && cd ../..

# Build the manual test program
gcc -o poc/buggy_chardev/test_trigger poc/buggy_chardev/test_trigger.c
```

### Step 2: Run the PoC

```bash
sudo bash poc/run_poc.sh
```

### Step 3 (optional): Run the Go Report Parser Unit Test

This verifies the report parser correctly recognizes `SYZLOGIC:` patterns,
without requiring root:

```bash
go test ./poc/ -v -run TestLogicBugDetection
```

## Expected Output

### `sudo bash poc/run_poc.sh`

```
=== Logickaller Logic Bug Detection PoC ===

[1/3] Loading buggy_chardev kernel module...
  OK: /dev/buggy_chardev created

[2/3] Triggering the logic bug...

read(fd, buf, 16) = 4096
LOGIC BUG DETECTED: read returned 4096 > count 16

  Kernel is alive - no crash, no panic, no KASAN.
  Syzkaller would report NOTHING here.

  But logickaller's executor checks: if read() returns more than count,
  it outputs SYZLOGIC and the manager reports it as a bug.

[3/3] Simulating logickaller executor detection...

  syscall: read(fd, buf, 16)
  kernel returned: 4096

  SYZLOGIC: read returned 4096 but count is 16

  >>> LOGIC BUG DETECTED by logickaller! <<<
  >>> Syzkaller would miss this entirely. <<<

Cleaning up...
Done.
```

### `go test ./poc/ -v -run TestLogicBugDetection`

```
=== RUN   TestLogicBugDetection
    logicbug_test.go:34: PASS: ContainsCrash correctly detects SYZLOGIC
    logicbug_test.go:44: PASS: Parse extracted title: "SYZLOGIC: read returned NUM but count is NUM"
    logicbug_test.go:55: PASS: Normal output does NOT trigger false positive
    logicbug_test.go:62: PASS: SYZFAIL still works alongside SYZLOGIC
--- PASS: TestLogicBugDetection (0.00s)
PASS
```

### Output Explanation

| Output Line | Meaning |
|---|---|
| `read(fd, buf, 16) = 4096` | Kernel `read()` returned 4096 bytes, but only 16 were requested |
| `LOGIC BUG DETECTED` | The `test_trigger` program verified the return value anomaly |
| `Kernel is alive` | No crash occurred — syzkaller would report nothing |
| `SYZLOGIC: read returned 4096 but count is 16` | **Logickaller's detection output** — this is what the executor emits and the manager saves as a bug |
