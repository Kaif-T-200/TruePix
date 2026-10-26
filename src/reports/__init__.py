"""Report export package for TruePix (Phase 2).

``json_report`` builds a schema-versioned JSON-serializable dict; ``pdf_report``
renders the same content as a PDF via reportlab. Both are pure functions of an
``AnalysisContext`` — no analyzer logic lives here.
"""
