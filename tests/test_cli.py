from __future__ import annotations

import json

from netprobe.cli import main


def test_version_and_help_do_not_probe(capsys) -> None:
    assert main(["--version"]) == 0
    assert "0.1.0" in capsys.readouterr().out

    assert main(["diagnose", "--help"]) == 0
    assert "diagnose" in capsys.readouterr().out.lower()


def test_doctor_json_is_single_document(capsys) -> None:
    assert main(["doctor", "--json"]) == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["schema_version"] == "1.0"
    assert "python" in payload
