import filecmp
import os
import subprocess
import sys

from sf_smartgate.conformance import FILES, run_dir

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SPEC = os.path.join(ROOT, 'spec', 'conformance')
DATA = os.path.join(ROOT, 'src', 'sf_smartgate', 'data', 'conformance')


def test_reference_passes_every_vector():
    total, fails = run_dir(SPEC)
    assert fails == [] and total >= 80


def test_vectors_are_what_the_generator_writes():
    r = subprocess.run([sys.executable, os.path.join(ROOT, 'spec', 'tools', 'make_vectors.py'), '--check'],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr


def test_wheel_copies_equal_the_spec():
    names = sorted(os.listdir(SPEC))
    assert names == sorted(os.listdir(DATA))
    assert set(FILES) <= set(names)
    for n in names:
        assert filecmp.cmp(os.path.join(SPEC, n), os.path.join(DATA, n), shallow=False), n


def test_bundled_vectors_run_from_the_package():
    from importlib.resources import as_file

    from sf_smartgate._bundled import path
    with as_file(path('conformance')) as d:
        total, fails = run_dir(str(d))
    assert not fails


def test_versions_agree():
    import pytest
    tomllib = pytest.importorskip('tomllib')

    from sf_smartgate import __version__
    with open(os.path.join(ROOT, 'pyproject.toml'), 'rb') as f:
        assert tomllib.load(f)['project']['version'] == __version__
    import json
    smart = json.load(open(os.path.join(ROOT, '.smart.json'), encoding='utf-8'))
    assert smart['version'] == __version__
    for rel in ('ports/node/package.json',):
        assert json.load(open(os.path.join(ROOT, rel), encoding='utf-8'))['version'] == __version__
