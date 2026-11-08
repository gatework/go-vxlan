#!/usr/bin/env python3
"""Guard package responsibilities using Go's production import graph."""
import json
import pathlib
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE = "github.com/gatework/go-vxlan"


def packages(root=ROOT, env=None):
    text = subprocess.check_output(["go", "list", "-json", "./..."], cwd=root, env=env, text=True)
    decoder = json.JSONDecoder()
    while text.strip():
        package, end = decoder.raw_decode(text.lstrip())
        yield package
        text = text.lstrip()[end:]


def within(path, roots):
    """Match package boundaries, including descendants without prefix lookalikes."""
    return any(path == root or path.startswith(root + "/") for root in roots)


def violations(graph):
    failures = []
    pure = {"parser", "collect", "configuration", "change", "review", "vendors", "internal/record", "internal/textparse"}
    forbidden_io = {"os", "io/fs", "net/http", "net/rpc", "database/sql", "path/filepath", "syscall"}
    transport = {"github.com/gatework/go-net-connector", "github.com/gatework/go-expect"}
    terminal = {"github.com/spf13", "golang.org/x/term"}
    for package in graph:
        relative = package["ImportPath"].removeprefix(MODULE).removeprefix("/")
        if within(relative, {"cli"}):
            failures.append("CLI must remain internal")
        for dependency in package.get("Imports", []):
            local = dependency.removeprefix(MODULE + "/")
            if relative == "" and dependency.startswith(MODULE + "/") and not within(local, {"internal/record"}):
                failures.append(f"root evidence -> {local}")
            if within(relative, {"parser"}) and within(local, {"vendors", "collect", "configuration", "change", "review"}):
                failures.append(f"parser -> {local}")
            if within(relative, {"collect"}) and within(local, {"vendors", "adapter", "internal/workflow"}):
                failures.append(f"collect must consume the selected profile, not {local}")
            if within(relative, {"configuration"}) and within(local, {"change", "review"}):
                failures.append(f"configuration -> {local}")
            if within(relative, {"change"}) and within(local, {"review"}):
                failures.append("change -> review")
            if within(relative, {"internal/workflow"}) and (
                within(local, {"internal/cli", "internal/bootstrap", "adapter"})
                or within(dependency, terminal | transport)
            ):
                failures.append(f"workflow -> {dependency}")
            if (relative == "" or within(relative, pure)) and (
                dependency == "net" or within(dependency, forbidden_io | transport | terminal | {"golang.org/x/sys"})
                or within(local, {"adapter", "report", "internal/cli", "internal/bootstrap", "internal/workflow"})
            ):
                failures.append(f"pure package {relative or 'root'} -> {dependency}")
        # Domain code must not hide application/transport dependencies behind a
        # local helper. Standard-library I/O stays a direct-import check because
        # otherwise ordinary fmt/time dependencies would become false positives.
        if relative == "" or within(relative, pure):
            for dependency in package.get("Deps", []):
                local = dependency.removeprefix(MODULE + "/")
                if within(dependency, transport | terminal) or within(
                    local, {"adapter", "report", "internal/cli", "internal/bootstrap", "internal/workflow"}
                ):
                    failures.append(f"pure package {relative or 'root'} transitively -> {dependency}")
                if relative == "" and dependency.startswith(MODULE + "/") and not within(local, {"internal/record"}):
                    failures.append(f"root evidence transitively -> {local}")
    return sorted(set(failures))


def main():
    failures = violations(packages())
    if failures:
        raise SystemExit("architecture violations:\n" + "\n".join(failures))
    print("PASS: production imports preserve evidence, domain, vendor, transport, and application boundaries")


if __name__ == "__main__":
    main()
