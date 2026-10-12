#!/usr/bin/env python3
"""
automode.py - auto-approve wrapper for interactive CLIs (Command Code etc.)

Usage:
    python automode.py cmd              # run `cmd` with auto-approve
    python automode.py --no-guard cmd   # also auto-approve "dangerous" commands
    python automode.py cmd --some-arg   # extra args are passed through

How it works:
    Runs the CLI inside a pseudo-terminal, so it behaves exactly as normal.
    When the screen shows a permission menu ("❯ 1. Yes ... No, tell ..."),
    it sends Enter, which picks option 1 (Yes). Everything else is passed
    straight through, so you can still type normally.

    If the prompt text contains something on the DENYLIST (rm -rf, sudo,
    force push, ...), it does NOT auto-approve, and rings the terminal bell
    so you can decide manually.
"""
import fcntl
import os
import pty
import re
import select
import signal
import struct
import sys
import termios
import time
import tty

# ---- config ---------------------------------------------------------------

# Menu is considered "a permission prompt" when both of these are on screen.
PROMPT_HEAD = re.compile(r"❯\s*1\.\s*Yes")
PROMPT_TAIL = re.compile(r"No,\s*tell")

# Never auto-approve if the prompt text matches any of these.
DENYLIST = [
    r"\brm\s+-[a-zA-Z]*[rf]",          # rm -r / rm -rf / rm -f
    r"\bsudo\b",
    r"git\s+push\s+.*(--force|-f\b)",
    r"git\s+reset\s+--hard",
    r"git\s+clean\s+-[a-zA-Z]*f",
    r"\bmkfs\b",
    r"\bdd\s+if=",
    r"curl[^|\n]*\|\s*(sh|bash|zsh)",
    r"wget[^|\n]*\|\s*(sh|bash|zsh)",
    r"chmod\s+-R",
    r"chown\s+-R",
    r"(?i)\bdrop\s+(table|database)\b",
    r">\s*/dev/sd",
    r":\(\)\s*\{",                       # fork bomb
]
DENY_RE = [re.compile(p) for p in DENYLIST]

SETTLE_DELAY = 0.25   # wait for the TUI to finish drawing before pressing Enter
COOLDOWN = 0.8        # ignore re-draws right after we answered
BUFFER_MAX = 8000     # chars of recent output kept for matching

ANSI_RE = re.compile(
    r"\x1b\[[0-9;?]*[ -/]*[@-~]"      # CSI sequences
    r"|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)"  # OSC sequences
    r"|\x1b[@-Z\\-_]"                 # other 2-char escapes
)


def strip_ansi(s: str) -> str:
    return ANSI_RE.sub("", s).replace("\r", "\n")


def copy_winsize(src_fd: int, dst_fd: int) -> None:
    try:
        size = fcntl.ioctl(src_fd, termios.TIOCGWINSZ, b"\0" * 8)
        fcntl.ioctl(dst_fd, termios.TIOCSWINSZ, size)
    except OSError:
        pass


def is_dangerous(text: str) -> str | None:
    for rx in DENY_RE:
        m = rx.search(text)
        if m:
            return m.group(0)
    return None


def main() -> int:
    args = sys.argv[1:]
    guard = True
    if args and args[0] == "--no-guard":
        guard = False
        args = args[1:]
    if not args:
        print(__doc__)
        return 2

    pid, master = pty.fork()
    if pid == 0:  # child: become the CLI
        try:
            os.execvp(args[0], args)
        except FileNotFoundError:
            print(f"automode: command not found: {args[0]}", file=sys.stderr)
            os._exit(127)

    stdin_fd = sys.stdin.fileno()
    stdout_fd = sys.stdout.fileno()
    copy_winsize(stdin_fd, master)

    def on_winch(_sig, _frm):
        copy_winsize(stdin_fd, master)
        try:
            os.kill(pid, signal.SIGWINCH)
        except ProcessLookupError:
            pass

    signal.signal(signal.SIGWINCH, on_winch)

    old_attrs = termios.tcgetattr(stdin_fd)
    tty.setraw(stdin_fd)

    buf = ""
    last_answer = 0.0
    exit_code = 0

    try:
        while True:
            try:
                rlist, _, _ = select.select([stdin_fd, master], [], [], 0.1)
            except InterruptedError:
                continue

            if stdin_fd in rlist:
                data = os.read(stdin_fd, 4096)
                if not data:
                    break
                os.write(master, data)

            if master in rlist:
                try:
                    data = os.read(master, 65536)
                except OSError:
                    break
                if not data:
                    break
                os.write(stdout_fd, data)
                buf += strip_ansi(data.decode("utf-8", errors="ignore"))
                buf = buf[-BUFFER_MAX:]

                if (
                    time.time() - last_answer > COOLDOWN
                    and PROMPT_HEAD.search(buf)
                    and PROMPT_TAIL.search(buf)
                ):
                    time.sleep(SETTLE_DELAY)
                    # Context = the last chunk of screen text before the menu
                    hit = is_dangerous(buf[-2500:]) if guard else None
                    if hit:
                        os.write(stdout_fd, b"\a")  # bell: needs a human
                    else:
                        os.write(master, b"\r")     # option 1 = Yes
                    last_answer = time.time()
                    buf = ""
    finally:
        termios.tcsetattr(stdin_fd, termios.TCSADRAIN, old_attrs)
        try:
            _, status = os.waitpid(pid, 0)
            exit_code = os.waitstatus_to_exitcode(status)
        except ChildProcessError:
            pass

    return exit_code


if __name__ == "__main__":
    sys.exit(main())