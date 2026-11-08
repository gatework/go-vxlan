#!/usr/bin/env python3
"""Guard package responsibilities using Go's production import graph."""
import json
import pathlib
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE = "github.com/gatework/go-vxlan"


def packages():
    text = subprocess.check_output(["go", "list", "-json", "./..."], cwd=ROOT, text=True)
    decoder = json.JSONDecoder()
    while text.strip():
        package, end = decoder.raw_decode(text.lstrip())
        yield package
        text = text.lstrip()[end:]


def main():
    failures = []
    pure = {"", "parser", "collect", "configuration", "change", "review", "vendors", "vendors/nxos", "internal/record", "internal/textparse"}
    forbidden_io = {"os", "os/exec", "io/fs", "net", "net/http", "net/rpc", "database/sql", "path/filepath", "syscall"}
    for package in packages():
        relative = package["ImportPath"].removeprefix(MODULE).removeprefix("/")
        if relative == "cli" or relative.startswith("cli/"):
            failures.append("CLI must remain internal")
        for dependency in package.get("Imports", []):
            local = dependency.removeprefix(MODULE + "/")
            if relative == "" and dependency.startswith(MODULE + "/") and local != "internal/record":
                failures.append(f"root evidence -> {local}")
            if relative == "parser" and (local.startswith("vendors") or local in {"collect", "configuration", "change", "review"}):
                failures.append(f"parser -> {local}")
            if relative == "collect" and (local.startswith("vendors") or local.startswith("adapter") or local.startswith("internal/workflow")):
                failures.append(f"collect must consume the selected profile, not {local}")
            if relative == "configuration" and local in {"change", "review"}:
                failures.append(f"configuration -> {local}")
            if relative == "change" and local == "review":
                failures.append("change -> review")
            if relative.startswith("internal/workflow") and (
                local.startswith(("internal/cli", "internal/bootstrap", "adapter"))
                or dependency.startswith(("github.com/spf13/", "golang.org/x/term", "github.com/gatework/go-net-connector/"))
            ):
                failures.append(f"workflow -> {dependency}")
            if relative in pure and (
                dependency in forbidden_io
                or dependency.startswith(("github.com/spf13/", "golang.org/x/term", "golang.org/x/sys/", "github.com/gatework/go-net-connector/", "github.com/gatework/go-expect"))
                or local.startswith(("adapter", "report", "internal/cli", "internal/bootstrap", "internal/workflow"))
            ):
                failures.append(f"pure package {relative or 'root'} -> {dependency}")
    if failures:
        raise SystemExit("architecture violations:\n" + "\n".join(sorted(set(failures))))
    print("PASS: production imports preserve evidence, domain, vendor, transport, and application boundaries")


if __name__ == "__main__":
    main()
