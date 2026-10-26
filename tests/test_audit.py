import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from scripts.audit import analyze, is_example, js_uses, parse_example, python_uses

ROOT = Path(__file__).resolve().parents[1]


class EnvTests(unittest.TestCase):
    def test_python_required(self):
        self.assertFalse(python_uses('import os\nx=os.environ["KEY"]', 'a.py')[0].optional)

    def test_python_optional(self):
        self.assertTrue(python_uses('import os\nx=os.getenv("KEY", "fallback")', 'a.py')[0].optional)

    def test_python_none_required(self):
        self.assertFalse(python_uses('import os\nx=os.getenv("KEY", None)', 'a.py')[0].optional)

    def test_python_get(self):
        self.assertEqual(python_uses('import os\nx=os.environ.get("KEY")', 'a.py')[0].name, "KEY")

    def test_python_dynamic_ignored(self):
        self.assertEqual(python_uses('import os\nx=os.getenv(var)', 'a.py'), [])

    def test_js_dot(self):
        self.assertEqual(js_uses('const x=process.env.API_ENDPOINT', 'app.ts')[0].name, 'API_ENDPOINT')

    def test_js_bracket(self):
        self.assertEqual(js_uses("const x=process.env['SVC_HOST']", 'app.ts')[0].name, 'SVC_HOST')

    def test_vite(self):
        self.assertEqual(js_uses('import.meta.env.VITE_FOO', 'app.ts')[0].channel, 'vite')

    def test_js_optional(self):
        self.assertTrue(js_uses('const x=process.env.X ?? 3', 'app.ts')[0].optional)

    def test_env_example_name(self):
        self.assertTrue(is_example(Path('.env.example')))

    def test_hidden_env_not_example(self):
        self.assertFalse(is_example(Path('.env.local')))

    def test_example_comment(self):
        declared, _ = parse_example('# BAD=secret\nexport GOOD=\n', 'x')
        self.assertEqual(declared, {'GOOD': 2})

    def test_duplicate_example(self):
        _, f = parse_example('A=1\nA=2\n', 'x')
        self.assertEqual(f[0].rule, 'ENV004')

    def test_safe_fixture(self):
        self.assertEqual(analyze(ROOT / 'examples' / 'safe'), [])

    def test_missing_required(self):
        f = analyze(ROOT / 'examples' / 'drift')
        self.assertTrue(any(x.rule == 'ENV002' and x.name == 'API_ENDPOINT' and x.severity == 'high' for x in f))

    def test_missing_optional(self):
        f = analyze(ROOT / 'examples' / 'drift')
        self.assertTrue(any(x.rule == 'ENV002' and x.name == 'CACHE_URL' and x.severity == 'low' for x in f))

    def test_secret_like_client_name(self):
        f = analyze(ROOT / 'examples' / 'drift')
        self.assertTrue(any(x.rule == 'ENV003' and x.name == 'VITE_PRIVATE_TOKEN' for x in f))

    def test_extra_optional_flag(self):
        f = analyze(ROOT / 'examples' / 'drift', check_unused=True)
        self.assertTrue(any(x.rule == 'ENV005' and x.name == 'OLD_SETTING' for x in f))

    def test_builtin_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / 'x.ts').write_text('console.log(process.env.NODE_ENV)')
            self.assertEqual(analyze(Path(tmp)), [ ])

    def test_missing_example(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / 'app.py').write_text('import os\nx=os.environ["NEEDED"]')
            self.assertTrue(any(x.rule == 'ENV001' for x in analyze(Path(tmp))))

    def test_does_not_read_real_env(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / '.env').write_text('PRIVATE_TOKEN=never-print-this-value')
            (Path(tmp) / 'app.py').write_text('import os\nx=os.environ["PRIVATE_TOKEN"]')
            f = analyze(Path(tmp))
            self.assertNotIn('never-print-this-value', repr(f))

    def test_subfolder_examples(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / 'nested'; p.mkdir()
            (p / '.env.sample').write_text('KEY=\n')
            (p / 'app.js').write_text('console.log(process.env.KEY)')
            self.assertEqual(analyze(Path(tmp)), [])

    def test_symlink_root_denied(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / 'linked'; p.symlink_to(ROOT / 'examples' / 'safe', target_is_directory=True)
            with self.assertRaises(ValueError):
                analyze(p)

    def test_cli_json_exit(self):
        p = subprocess.run([sys.executable, str(ROOT / 'scripts/audit.py'), str(ROOT / 'examples/drift'), '--format', 'json'], capture_output=True, text=True)
        self.assertEqual(p.returncode, 2)
        self.assertGreater(json.loads(p.stdout)['count'], 0)

    def test_cli_safe_exit(self):
        p = subprocess.run([sys.executable, str(ROOT / 'scripts/audit.py'), str(ROOT / 'examples/safe')], capture_output=True, text=True)
        self.assertEqual(p.returncode, 0)


if __name__ == '__main__':
    unittest.main()
