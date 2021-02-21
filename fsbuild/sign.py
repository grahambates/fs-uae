#!/usr/bin/env python3

import os
import sys
import time
import subprocess


def plugin_name():
    # FIXME: Read from external config
    return "FS-UAE"


def plugin_arch():
    # FIXME: Detect properly
    return "x86-64"


def macos_app_bundle():
    plugin = plugin_name()
    arch = plugin_arch()
    return f"fsbuild/_build/{plugin}/macOS/{arch}/{plugin}.app"


def q(arg):
    if " " in arg:
        return f'"{arg}"'
    return arg


def macos_sign():
    # Signing sometimes fails due to Apple errors (timeouts, etc). So we try
    # multiple times before giving up.
    for i in range(20):
        args = [
            "codesign",
            "-f",
            "--deep",
            "--options=runtime",
            "--entitlements",
            "fsbuild/Entitlements.plist",
            "-s",
            "Developer ID Application",
            macos_app_bundle(),
        ]
        print(" ".join(f"{q(a)}" for a in args))
        p = subprocess.Popen(args)
        if p.wait() == 0:
            break
        time.sleep(1.0 * i)
        print("Attempt", i + 2)
    else:
        print("Giving up")
        sys.exit(1)


def main():
    if sys.platform == "darwin":
        macos_sign()


if __name__ == "__main__":
    main()
