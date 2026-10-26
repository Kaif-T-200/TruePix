"""Tests for ``src.batch`` — single-file runner, batch isolation,
progress callback contract, and CSV export shape.

Behaviour locked in here:
- ``run_one`` returns a ``BatchRow`` summary for a valid image.
- One bad file (missing or undecodable) never aborts the batch.
- ``run_batch`` calls ``progress_cb(i, total, filename)`` once per file,
  0-based, before the file is analyzed.
- ``to_csv`` renders a pandas CSV without the ``ctx`` column.
"""

from __future__ import annotations

import csv
import io
import re

from src.batch import BatchRow, run_batch, run_one, to_csv
from src.risk_engine import (
    ELEVATED,
    HIGH,
    HIGH_CONFIDENCE_AI,
    INCONCLUSIVE,
    INSUFFICIENT,
    LOW,
    MODERATE,
    ORIGIN_UNKNOWN,
    PROVEN_AI,
)

_KNOWN_VERDICTS = {
    PROVEN_AI,
    HIGH_CONFIDENCE_AI,
    ORIGIN_UNKNOWN,
    INSUFFICIENT,
    INCONCLUSIVE,
    LOW,
    MODERATE,
    ELEVATED,
    HIGH,
}

_HEX64 = re.compile(r"[0-9a-f]{64}")


def test_run_one_returns_summary_row(rgb_image):
    row = run_one(rgb_image, "rgb.png")

    assert isinstance(row, BatchRow)
    assert row.ok is True
    assert row.error == ""
    assert _HEX64.fullmatch(row.sha256)
    assert row.filename == "rgb.png"

    # Verdict comes from the risk engine; a random-noise PNG can land in
    # any band, but must be one of the engine's verdict constants.
    assert row.verdict in _KNOWN_VERDICTS
    assert isinstance(row.assessment, str) and row.assessment
    assert isinstance(row.evidence_score, float)
    assert 0.0 <= row.evidence_score <= 1.0
    assert isinstance(row.confidence, str) and row.confidence

    # ctx carries the full analysis and agrees with the summary fields.
    assert row.ctx is not None
    assert row.ctx.image_path == rgb_image
    assert row.ctx.risk is not None
    assert row.verdict == row.ctx.risk["verdict"]
    assert row.assessment == row.ctx.risk["assessment"]
    assert row.evidence_score == row.ctx.risk["evidence_score"]
    assert row.confidence == row.ctx.risk["confidence"]


def test_run_batch_missing_file_is_rejected_not_fatal(tmp_path, jpg_image):
    missing = str(tmp_path / "no_such_file.png")

    rows = run_batch(
        [
            (missing, "ghost.png"),
            (jpg_image, "photo.jpg"),
        ]
    )

    # No exception escaped and both rows came back.
    assert len(rows) == 2
    bad, good = rows

    assert bad.filename == "ghost.png"
    assert bad.ok is False
    assert bad.error  # non-empty human-readable reason
    assert bad.sha256 == ""
    assert bad.verdict is None
    assert bad.assessment is None
    assert bad.evidence_score is None
    assert bad.confidence is None
    assert bad.ctx is None

    # The good file after the bad one still succeeds.
    assert good.ok is True
    assert good.error == ""
    assert _HEX64.fullmatch(good.sha256)
    assert good.ctx is not None
    assert good.verdict in _KNOWN_VERDICTS

    # An undecodable (but present) file is likewise rejected without raising.
    garbage = tmp_path / "not_an_image.png"
    garbage.write_bytes(b"\x00\x01\x02 definitely not an image")
    rows2 = run_batch([(str(garbage), "broken.png"), (jpg_image, "photo2.jpg")])
    assert len(rows2) == 2
    assert rows2[0].ok is False
    assert rows2[0].error
    assert rows2[0].verdict is None
    assert rows2[0].assessment is None
    assert rows2[0].evidence_score is None
    assert rows2[0].ctx is None
    assert rows2[1].ok is True


def test_run_batch_with_progress_callback(rgb_image, jpg_image):
    calls = []

    def progress_cb(i, total, name):
        calls.append((i, total, name))

    rows = run_batch(
        [(rgb_image, "a.png"), (jpg_image, "b.jpg")],
        progress_cb=progress_cb,
    )

    assert len(rows) == 2
    # Signature is (i, total, filename): 0-based index, batch size, name.
    assert len(calls) == 2
    assert calls[0] == (0, 2, "a.png")
    assert calls[1] == (1, 2, "b.jpg")
    assert [c[0] for c in calls] == [0, 1]
    assert {c[1] for c in calls} == {2}
    assert all(r.ok for r in rows)


def test_csv_export_shape(tmp_path, rgb_image):
    rows = run_batch(
        [
            (rgb_image, "good.png"),
            (str(tmp_path / "missing.png"), "missing.png"),
        ]
    )

    text = to_csv(rows)
    assert isinstance(text, str)

    parsed = list(csv.reader(io.StringIO(text)))
    header = parsed[0]
    data = parsed[1:]

    assert header == [
        "filename",
        "sha256",
        "ok",
        "error",
        "verdict",
        "assessment",
        "evidence_score",
        "confidence",
    ]
    assert len(data) == len(rows) == 2

    # ctx must not leak into the export.
    assert "ctx" not in header
    assert "ctx" not in text
    assert "AnalysisContext" not in text

    # Successful row is fully rendered.
    assert data[0][0] == "good.png"
    assert _HEX64.fullmatch(data[0][1])
    assert data[0][2] == "True"
    assert data[0][3] == ""
    assert data[0][4] in _KNOWN_VERDICTS
    assert data[0][5]
    assert re.fullmatch(r"\d+\.\d{3}", data[0][6])
    assert data[0][7]

    # Failed row keeps its error but blanks out the result columns.
    assert data[1][0] == "missing.png"
    assert data[1][1] == ""
    assert data[1][2] == "False"
    assert data[1][3]  # error message survives
    assert data[1][4] == ""
    assert data[1][5] == ""
    assert data[1][6] == ""
    assert data[1][7] == ""

    # Trailing newline only: exactly one header + one line per row.
    assert text.endswith("\n")
    assert text.count("\n") == 1 + len(rows)
