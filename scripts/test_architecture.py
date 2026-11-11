#!/usr/bin/env python3
"""Exercise architecture rules against real temporary Go package graphs."""
import importlib.util
import os
import pathlib
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location(
    "architecture", pathlib.Path(__file__).with_name("check-architecture.py")
)
architecture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(architecture)


class ArchitectureTest(unittest.TestCase):
    def graph(self, source, dependency, via=None):
        with tempfile.TemporaryDirectory(prefix="vxlan-architecture-") as directory:
            root = pathlib.Path(directory)
            (root / "go.mod").write_text(f"module {architecture.MODULE}\n\ngo 1.26.0\n")
            source_dir = root / source
            source_dir.mkdir(parents=True, exist_ok=True)
            if dependency.startswith(architecture.MODULE + "/"):
                target = root / dependency.removeprefix(architecture.MODULE + "/")
                target.mkdir(parents=True, exist_ok=True)
                (target / "target.go").write_text("package fixture\n")
            imports = f'import _ "{dependency}"\n' if dependency else ""
            if via is not None:
                helper = root / via
                helper.mkdir(parents=True, exist_ok=True)
                (helper / "helper.go").write_text("package fixture\n" + imports)
                imports = f'import _ "{architecture.MODULE}/{via}"\n'
            (source_dir / "source.go").write_text("package fixture\n" + imports)
            env = dict(os.environ, GOWORK="off", GOFLAGS="-mod=readonly")
            return list(architecture.packages(root, env))

    def test_forbidden_package_boundaries(self):
        module = architecture.MODULE
        for source, dependency in [
            ("rules/nested", "os"),
            ("configuration/index", "net/http/httputil"),
            ("parser/model", module + "/vendors/nxos/grammar"),
            ("collect/batch", module + "/vendors/nxos"),
            ("configuration/index", module + "/change/render"),
            ("change/render", module + "/rules/catalog"),
            ("rules/catalog", module + "/configuration/index"),
            ("fabric/model", module + "/vendors/nxos"),
            ("internal/workflow/apply/journal", module + "/internal/bootstrap/options"),
            ("internal/workflow/batch", module + "/adapter/device"),
            ("", module + "/rules/catalog"),
            ("cli/command", ""),
        ]:
            with self.subTest(source=source, dependency=dependency):
                self.assertTrue(architecture.violations(self.graph(source, dependency)))

    def test_domain_helper_cannot_hide_application_dependency(self):
        for source, via, dependency in [
            ("rules/nested", "internal/shared", "internal/bootstrap/options"),
            ("", "internal/record/helper", "report/store"),
        ]:
            with self.subTest(source=source):
                graph = self.graph(source, architecture.MODULE + "/" + dependency, via)
                self.assertTrue(any("transitively" in error for error in architecture.violations(graph)))

    def test_allowed_package_boundaries(self):
        module = architecture.MODULE
        for source, dependency in [
            ("", module + "/internal/record/json"),
            ("rules/catalog", module + "/fabric/model"),
            ("rules/catalog", module + "/change/render"),
            ("configuration/index", "net/netip"),
            ("internal/workflow/batch", module + "/report/store"),
            ("internal/cli/command", module + "/internal/bootstrap/options"),
        ]:
            with self.subTest(source=source, dependency=dependency):
                self.assertEqual([], architecture.violations(self.graph(source, dependency)))


if __name__ == "__main__":
    unittest.main()
