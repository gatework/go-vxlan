#!/usr/bin/env python3
"""Verify versioned dependencies and candidate-source consumption, without devices."""
import json
import os
import pathlib
import shutil
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
DEPENDENCIES = {
    "github.com/gatework/go-net-connector": "v0.5.0",
    "github.com/gatework/go-expect": "v0.4.2",
}


def run(args, cwd, *, capture=False, **overrides):
    env = dict(os.environ, **overrides, GOWORK="off", GOFLAGS="-mod=readonly")
    return subprocess.run(
        args, cwd=cwd, env=env, check=True, text=True, capture_output=capture
    ).stdout


def verify_dependencies(cwd):
    for path, version in DEPENDENCIES.items():
        module = json.loads(run(["go", "list", "-m", "-json", path], cwd, capture=True))
        if module.get("Version") != version or module.get("Replace"):
            raise RuntimeError(f"dependency must resolve directly to {path}@{version}")


def main():
    module = json.loads(run(["go", "mod", "edit", "-json"], ROOT, capture=True))
    if module.get("Replace"):
        raise RuntimeError("candidate go.mod must not contain replacements")
    run(["python3", "scripts/check-architecture.py"], ROOT)
    run(["python3", "scripts/test_architecture.py"], ROOT)
    verify_dependencies(ROOT)
    run(["go", "mod", "verify"], ROOT)
    run(["go", "mod", "tidy", "-diff"], ROOT)

    with tempfile.TemporaryDirectory(prefix="go-vxlan-delivery-") as temporary:
        temp = pathlib.Path(temporary)
        isolated = temp / "source"
        shutil.copytree(
            ROOT,
            isolated,
            ignore=shutil.ignore_patterns(
                ".git", ".work", ".superpowers", "bin", "dist", "go.work", "go.work.sum",
                ".env", "vxlans", "vxlan-executions", "__pycache__",
            ),
        )
        verify_dependencies(isolated)
        run(["go", "test", "./..."], isolated)
        for system in ("darwin", "linux"):
            for arch in ("amd64", "arm64"):
                run(
                    ["go", "build", "-o", str(temp / f"vxlan-{system}-{arch}"), "./cmd/vxlan"],
                    isolated, GOOS=system, GOARCH=arch, CGO_ENABLED="0",
                )

        consumer = temp / "consumer"
        consumer.mkdir()
        # Only the unpublished root candidate is local. Its dependencies must
        # remain versioned: this is a source-consumer smoke, not a release gate.
        (consumer / "go.mod").write_text(
            "module example.invalid/consumer\n\ngo 1.26.0\n\n"
            "require github.com/gatework/go-vxlan v0.0.0\n"
            "replace github.com/gatework/go-vxlan => " + json.dumps(str(isolated)) + "\n"
        )
        (consumer / "main.go").write_text(
            'package main\nimport("fmt"; nxos "github.com/gatework/go-vxlan/vendors/nxos"; '
            '_ "github.com/gatework/go-vxlan/adapter/netconnector"; '
            '_ "github.com/gatework/go-vxlan/collect"; '
            '_ "github.com/gatework/go-vxlan/configuration"; '
            '_ "github.com/gatework/go-vxlan/change"; '
            '_ "github.com/gatework/go-vxlan/review")\n'
            'func main(){o,e:=nxos.ParseConfigChecked("hostname LEAF\\n",true);'
            'if e!=nil||!o.Complete(){panic("parse failed")};fmt.Println(o)}\n'
        )
        run(["go", "mod", "tidy"], consumer)
        verify_dependencies(consumer)
        run(["go", "run", "."], consumer)

        bindir = temp / "installed"
        bindir.mkdir()
        run(["go", "install", "./cmd/vxlan"], isolated, GOBIN=str(bindir))
        binary = str(bindir / "vxlan")
        build_info = run(["go", "version", "-m", binary], temp, capture=True)
        for path, version in DEPENDENCIES.items():
            if f"\tdep\t{path}\t{version}\t" not in build_info:
                raise RuntimeError(f"installed binary is missing {path}@{version}")
        run([binary, "--version"], temp)
        sample = consumer / "sample.cfg"
        sample.write_text("hostname LEAF\n")
        run([binary, "parse", "--model", "N9K", "--complete", "--json", "--file", str(sample)], temp)

    print("PASS: versioned dependencies, four target builds, isolated tests, candidate-source consumer, installed CLI")


if __name__ == "__main__":
    main()
