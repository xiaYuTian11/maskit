"""Release build safety using fake tools and disposable input directories."""
import ast
import json
import os
import pathlib
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ModelBundleTests(unittest.TestCase):
    def model_resources(self, directory):
        spec = ast.parse((ROOT / "engine/maskit-engine.spec").read_text())
        fn = next(n for n in spec.body if isinstance(n, ast.FunctionDef) and n.name == "_model_resources")
        namespace = {}
        exec(compile(ast.Module(body=[fn], type_ignores=[]), "model-resources", "exec"), namespace)
        return namespace["_model_resources"](directory)

    def test_absent_model_is_explicitly_lightweight(self):
        with tempfile.TemporaryDirectory() as temp:
            self.assertEqual(self.model_resources(Path(temp)), [])

    def test_partial_or_empty_model_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            model = root / "models/ner_mini_zh"
            model.mkdir(parents=True)
            (model / "model_quantized.onnx").write_bytes(b"synthetic model")
            with self.assertRaises(SystemExit):
                self.model_resources(root)
            (model / "tokenizer.json").write_text("{}")
            (model / "config.json").touch()
            with self.assertRaises(SystemExit):
                self.model_resources(root)
            (model / "config.json").write_text("{}")
            self.assertEqual(self.model_resources(root), [(str(model), "models/ner_mini_zh")])


@unittest.skipUnless(os.name == "posix" and shutil.which("bash"), "Linux build wrapper requires bash")
class LinuxBuildSafetyTests(unittest.TestCase):
    FIXTURES = ["engine/config.json", "engine/proxy_token", "engine/shield-events.sqlite3",
                "engine/debug-test.log", "src-tauri/resources/engine/installed-marker"]
    PACKAGE_ENTRIES = ("resources/engine/MaskitEngine",
                       "resources/engine/_internal/transparent.py",
                       "resources/engine/_internal/inspection.py",
                       "resources/engine/_internal/protocol_contracts.py",
                       "resources/engine/_internal/onboarding.py",
                       "resources/engine/_internal/skill_bundle/SKILL.md",
                       "resources/engine/_internal/models/ner_mini_zh/model_quantized.onnx")

    def run_build(self, package_listing):
        """Run build.sh --release-only against a fake toolchain; return (result, root)."""
        temp = tempfile.mkdtemp(prefix="maskit-build-test-")
        self.addCleanup(shutil.rmtree, temp, True)
        root = Path(temp)
        shutil.copy2(ROOT / "build.sh", root / "build.sh")
        (root / "engine/models/ner_mini_zh").mkdir(parents=True)
        for name in ("frontend", "src-tauri/resources/engine", "tmpdir", "stage", "bin"):
            (root / name).mkdir(parents=True)
        for name in self.FIXTURES:
            (root / name).write_text("synthetic runtime: preserve")
        for name in ("model_quantized.onnx", "tokenizer.json", "config.json"):
            (root / "engine/models/ner_mini_zh" / name).write_text("synthetic model")
        fake = root / "bin/tool.py"
        fake.write_text("#!" + sys.executable + "\n" + r'''
import json, os, pathlib, subprocess, sys
name = pathlib.Path(sys.argv[0]).name
args = sys.argv[1:]
root = pathlib.Path(os.environ["BUILD_TEST_ROOT"])
with (root / "calls.jsonl").open("a") as f:
    f.write(json.dumps([name, args]) + "\n")
if name == "python":
    if args[:1] == ["-"]:
        raise SystemExit(subprocess.run([os.environ["REAL_PYTHON"], *args], input=sys.stdin.buffer.read()).returncode)
    if args[:2] == ["-m", "PyInstaller"]:
        pathlib.Path(args[args.index("--workpath") + 1]).mkdir(parents=True, exist_ok=True)
        out = pathlib.Path(args[args.index("--distpath") + 1]) / "MaskitEngine"
        (out / "_internal").mkdir(parents=True)
        (out / "MaskitEngine").write_text("synthetic executable")
        (out / "MaskitEngine").chmod(0o755)
    elif args[:1] == ["tests/smoke_transport.py"]:
        assert "--engine" in args and "--ner" in args
        assert pathlib.Path(args[args.index("--engine") + 1]).is_file()
    elif args[:1] == ["tests/smoke_packaged_panel.py"]:
        assert "--engine" in args and "--expect-ner" in args
        assert pathlib.Path(args[args.index("--engine") + 1]).is_file()
    elif args[:1] == ["scripts/verify-all.py"]:
        assert (root / "frontend/node_modules").is_dir(), "dependencies must precede gates"
    elif args == ["--version"]:
        print("Python 3.13")
elif name == "npm":
    if "ci" in args:
        (root / "frontend/node_modules").mkdir()
    elif args == ["--version"]:
        print("10.0.0")
elif name == "dpkg-deb":
    if args[:1] == ["-c"]:
        sys.stdout.write(os.environ["BUILD_TEST_PACKAGE_LISTING"])
elif name == "node":
    if args == ["--version"]:
        print("v22.12.0")
    else:
        cfg = json.loads(args[args.index("--config") + 1])
        assert cfg["bundle"]["createUpdaterArtifacts"] is False
        assert cfg["build"]["beforeBuildCommand"] is None
        assert list(cfg["bundle"]["resources"].values()) == ["resources/engine/"]
        assert "--locked" in args
        out = pathlib.Path(os.environ["CARGO_TARGET_DIR"]) / "release/bundle/deb"
        out.mkdir(parents=True)
        (out / "synthetic.deb").write_text("synthetic package")
''')
        fake.chmod(0o755)
        for name in ("python", "node", "npm", "cargo", "rustc", "pkg-config", "dpkg-deb"):
            (root / "bin" / name).symlink_to(fake.name)
        env = {k: v for k, v in os.environ.items() if k not in (
            "CARGO_TARGET_DIR", "TAURI_SIGNING_PRIVATE_KEY", "MASKIT_UPDATER_PRIVATE_KEY",
            "MASKIT_BUILD_STAGE")}
        env.update(PATH=str(root / "bin") + os.pathsep + env.get("PATH", ""),
                   MASKIT_PYTHON=str(root / "bin/python"), BUILD_TEST_ROOT=str(root),
                   REAL_PYTHON=sys.executable, TMPDIR=str(root / "tmpdir"),
                   MASKIT_BUILD_STAGE=str(root / "stage"),
                   BUILD_TEST_PACKAGE_LISTING=package_listing)
        result = subprocess.run([shutil.which("bash"), str(root / "build.sh"),
                                 "--release-only", "--bundles", "deb"],
                                env=env, text=True, capture_output=True, timeout=60)
        return result, root

    def deb_listing(self, *entries):
        return "".join("-rwxr-xr-x 0/0 1 2026-10-02 15:00 usr/lib/Maskit/%s\n" % e
                       for e in entries)

    def test_release_only_preserves_runtime_and_uses_frozen_smoke(self):
        result, root = self.run_build(self.deb_listing(*self.PACKAGE_ENTRIES))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        for name in self.FIXTURES:
            self.assertEqual((root / name).read_text(), "synthetic runtime: preserve")
        self.assertFalse((root / "dist_engine").exists())
        self.assertFalse((root / "src-tauri/tauri.unsigned.json").exists())
        calls = [json.loads(line) for line in (root / "calls.jsonl").read_text().splitlines()]
        self.assertTrue(any(args[:1] == ["tests/smoke_transport.py"] for _, args in calls))
        self.assertTrue(any(args[:1] == ["tests/smoke_packaged_panel.py"] for _, args in calls))
        # 暂存根与 cargo target 必须同根：一次构建的产物散在两个目录时，清理和取证都会踩空。
        self.assertTrue(list((root / "stage/tauri-target/release/bundle/deb").glob("*.deb")))
        self.assertEqual(list((root / "tmpdir").iterdir()), [], "staging must not touch TMPDIR")
        self.assertTrue(any(name == "dpkg-deb" and args[:1] == ["-c"] for name, args in calls),
                        "package contents were never inspected")

    def test_package_without_engine_aborts_release(self):
        """包里没有引擎/模型时必须中止：这类产物体积正常、装完才在启动时报「引擎缺失」。"""
        for listing in ("", self.deb_listing(*self.PACKAGE_ENTRIES[:2])):
            result, _ = self.run_build(listing)
            self.assertNotEqual(result.returncode, 0, "empty/incomplete package was released")
            self.assertIn("缺少", result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
