from pathlib import Path
from hardener.remediation import update_key_value


def test_update_key_value_dry_run(tmp_path):
    path = tmp_path / "sshd_config"
    path.write_text("PermitRootLogin yes\n")
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    update_key_value(str(path), "PermitRootLogin", "no", run_dir, dry_run=True)
    assert path.read_text() == "PermitRootLogin yes\n"


def test_update_key_value_write(tmp_path):
    path = tmp_path / "sshd_config"
    path.write_text("PermitRootLogin yes\n")
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    update_key_value(str(path), "PermitRootLogin", "no", run_dir, dry_run=False)
    assert "PermitRootLogin no" in path.read_text()
    assert (run_dir / "manifest.jsonl").exists()
