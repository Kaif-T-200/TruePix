"""Evidence & Risk Engine for TruePix (Phase 8).

Combines the structured outputs of the metadata, C2PA, forensics, visual-artifact
and AI-detector modules into a single explainable assessment. It does NOT treat
"number of findings = risk" and never emits a calibrated AI probability.

Design principles:
  * Each evidence *family* has a bounded contribution (double-counting protection).
  * Source reliability is explicit and documented; unverified C2PA is weighted
    lower than verified provenance. Unverified C2PA with AI-generation hints
    (e.g. SynthID markers) is treated as an AI-lean signal; missing
    C2PA/metadata adds no AI risk.
  * Independent corroborating families raise confidence; conflicting strong signals
    yield INCONCLUSIVE rather than a forced binary.
  * The internal "Evidence Score" (0..1) is explicitly NOT a probability.
  * Fully deterministic, CPU-only, no image reprocessing, no network.
"""

from __future__ import annotations

# Direction of an individual piece of evidence.
AI_INDICATOR = "AI_INDICATOR"
AUTHENTICITY_SUPPORT = "AUTHENTICITY_SUPPORT"
NEUTRAL = "NEUTRAL"

# Assessment bands.
LOW = "LOW"
MODERATE = "MODERATE"
ELEVATED = "ELEVATED"
HIGH = "HIGH"
INSUFFICIENT = "INSUFFICIENT_EVIDENCE"
INCONCLUSIVE = "INCONCLUSIVE"

# Strong verdict classes.  Only VERIFIED C2PA AI provenance is definitive;
# pixels and model scores can never prove origin by themselves.
PROVEN_AI = "PROVEN_AI_GENERATION"
HIGH_CONFIDENCE_AI = "HIGH_CONFIDENCE_AI_LIKELY"
ORIGIN_UNKNOWN = "ORIGIN_UNKNOWN"

# Per-family maximum contribution to the AI-evidence total (double-count guard).
# Values are documented: provenance (if verified) is strongest, forensic/visual
# heuristics are deliberately weak, metadata and an optional detector are moderate.
FAMILY_CAP = {
    "metadata": 0.25,
    "provenance": 0.30,
    "forensics": 0.35,
    "visual_artifacts": 0.20,
    "ai_detector": 0.30,
    "synthid": 0.20,  # unverified disclosure only; never definitive
    # Phase-3 families. Caps are deliberately LOW: compression history and
    # CFA presence/absence are weak signals with heavy confounds (screenshots,
    # resizes, messaging apps) and must rarely move a verdict on their own.
    "jpeg_ghost": 0.15,   # transformation context; AUTHENTICITY_SUPPORT only
    "cfa": 0.10,          # camera-pipeline hint; absence stays NEUTRAL
}
# Base reliability per family. Provenance is overridden to 0.9 only when VERIFIED;
# present_unverified provenance carries lower reliability (0.3) but AI-declaration
# findings from unverified C2PA (e.g. SynthID markers) still count as AI-lean signals.
RELIABILITY = {
    "metadata": 0.50,
    "provenance_unverified": 0.30,
    "provenance_verified": 0.90,
    "forensics": 0.45,
    "visual_artifacts": 0.35,
    "ai_detector": 0.60,
    "synthid": 0.35,  # raw-byte disclosure is not cryptographic verification
    # Phase-3 families: conservative reliability for confound-heavy signals.
    "jpeg_ghost": 0.30,
    "cfa": 0.35,
}
SEV_W = {"Critical": 1.0, "High": 0.8, "Medium": 0.6, "Low": 0.4, "Informational": 0.2}
CONF_W = {"High": 1.0, "Medium": 0.7, "Low": 0.4, "Unknown": 0.3, None: 0.3}

# Band thresholds on the (capped, scaled) AI-evidence total.
BAND_LOW = 0.15
BAND_MOD = 0.45
BAND_ELEV = 0.70


def _weight(severity, confidence, reliability) -> float:
    return SEV_W.get(severity, 0.3) * CONF_W.get(confidence, 0.3) * reliability


def _classify(finding: dict, module: str) -> dict | None:
    """Map a finding to an evidence item (family, direction, reliability)."""
    title = (finding.get("title") or "").lower()
    sev = finding.get("severity")
    conf = finding.get("confidence")

    if module == "metadata":
        if "ai-generation software" in title:
            return {"family": "metadata", "dir": AI_INDICATOR,
                    "rel": RELIABILITY["metadata"], "sev": sev, "conf": conf,
                    "fid": finding.get("id")}
        return {"family": "metadata", "dir": NEUTRAL,
                "rel": RELIABILITY["metadata"], "sev": sev, "conf": conf,
                "fid": finding.get("id")}

    if module == "c2pa":
        status = finding.get("_status")  # injected by caller
        if status == "VERIFIED":
            rel = RELIABILITY["provenance_verified"]
            if "ai-generation provenance" in title:
                d = AI_INDICATOR
            elif "editing activity" in title:
                d = AUTHENTICITY_SUPPORT
            else:
                d = NEUTRAL
        elif status == "PRESENT_UNVERIFIED":
            # Unverified provenance: AI-declaration findings (from SynthID /
            # generative-AI C2PA hints) are AI-leaning evidence at lower
            # reliability. Non-AI findings stay contextual (neutral).
            rel = RELIABILITY["provenance_unverified"]
            if "AI generation" in title or "ai generation" in title:
                d = AI_INDICATOR
                sev = sev or "Medium"   # cap to Medium even if source said High
            else:
                d = NEUTRAL
        else:
            rel = RELIABILITY["provenance_unverified"]
            d = NEUTRAL  # not-found / unsupported / error provenance is contextual only
        return {"family": "provenance", "dir": d, "rel": rel,
                "sev": sev, "conf": conf, "fid": finding.get("id")}

    if module == "forensics":
        # Forensics can now explicitly label transformation/style observations
        # as CONTEXT.  They must remain visible in the report but must not be
        # counted as AI evidence (a screenshot or illustration is not proof of
        # AI generation).
        direction = finding.get("evidence_direction", NEUTRAL)
        if direction not in (AI_INDICATOR, AUTHENTICITY_SUPPORT, NEUTRAL):
            direction = NEUTRAL
        return {"family": "forensics", "dir": direction,
                "rel": RELIABILITY["forensics"], "sev": sev, "conf": conf,
                "fid": finding.get("id")}

    if module == "artifacts":
        direction = finding.get("evidence_direction", NEUTRAL)
        if direction not in (AI_INDICATOR, AUTHENTICITY_SUPPORT, NEUTRAL):
            direction = NEUTRAL
        return {"family": "visual_artifacts", "dir": direction,
                "rel": RELIABILITY["visual_artifacts"], "sev": sev, "conf": conf,
                "fid": finding.get("id")}

    if module == "ai_detector":
        pred = finding.get("_prediction")
        if pred in ("AI_GENERATED", "LIKELY_AI"):
            d = AI_INDICATOR
        elif pred == "LIKELY_AUTHENTIC":
            d = AUTHENTICITY_SUPPORT
        else:
            d = NEUTRAL
        return {"family": "ai_detector", "dir": d,
                "rel": RELIABILITY["ai_detector"], "sev": sev, "conf": conf,
                "fid": finding.get("id"),
                "strong_consensus": bool((finding.get("_ensemble") or {}).get(
                    "strong_consensus", False))}

    if module == "jpeg_ghost":
        # Compression history is transformation context. A detected JPEG
        # past is consistent with screenshots/messengers/edits — it must
        # never count as AI evidence, so it stays NEUTRAL here and the
        # finding itself carries no AI direction.
        direction = finding.get("evidence_direction", NEUTRAL)
        if direction not in (AI_INDICATOR, AUTHENTICITY_SUPPORT, NEUTRAL):
            direction = NEUTRAL
        return {"family": "jpeg_ghost", "dir": direction,
                "rel": RELIABILITY["jpeg_ghost"], "sev": sev, "conf": conf,
                "fid": finding.get("id")}

    if module == "cfa":
        # CFA presence weakly supports a camera pipeline (the analyzer only
        # sets AUTHENTICITY_SUPPORT on detection). Absence findings arrive
        # as NEUTRAL by construction and stay that way.
        direction = finding.get("evidence_direction", NEUTRAL)
        if direction not in (AI_INDICATOR, AUTHENTICITY_SUPPORT, NEUTRAL):
            direction = NEUTRAL
        return {"family": "cfa", "dir": direction,
                "rel": RELIABILITY["cfa"], "sev": sev, "conf": conf,
                "fid": finding.get("id")}

    return None


def _collect(results: dict) -> list[dict]:
    items = []
    # Metadata
    for f in (results.get("metadata") or {}).get("findings", []):
        it = _classify(f, "metadata")
        if it:
            items.append(it)
    # C2PA (inject status so classify can branch)
    c2pa = results.get("c2pa") or {}
    for f in c2pa.get("findings", []):
        ff = dict(f)
        ff["_status"] = c2pa.get("status")
        it = _classify(ff, "c2pa")
        if it:
            items.append(it)
    # Forensics
    for f in (results.get("forensics") or {}).get("findings", []):
        it = _classify(f, "forensics")
        if it:
            items.append(it)
    # Artifacts
    for f in (results.get("artifacts") or {}).get("findings", []):
        it = _classify(f, "artifacts")
        if it:
            items.append(it)
    # JPEG history (Phase 3)
    for f in (results.get("jpeg_ghost") or {}).get("findings", []):
        it = _classify(f, "jpeg_ghost")
        if it:
            items.append(it)
    # CFA / demosaicing (Phase 3)
    for f in (results.get("cfa") or {}).get("findings", []):
        it = _classify(f, "cfa")
        if it:
            items.append(it)
    # AI detector
    ai = results.get("ai_detector") or {}
    if ai.get("status") == "AVAILABLE":
        for f in ai.get("findings", []):
            ff = dict(f)
            ff["_prediction"] = ai.get("prediction")
            it = _classify(ff, "ai_detector")
            if it:
                items.append(it)
    # Provenance / watermark (e.g. SynthID). Only contributes when explicitly
    # DETECTED; NOT_DETECTED is NOT treated as proof of authenticity.
    synth = results.get("synthid") or {}
    if synth.get("status") == "DETECTED":
        # Only an explicit C2PA disclosure is AI-leaning. Experimental pixel
        # probes, DWT/DCT correlations, and visible-stamp heuristics remain
        # visible in the report but cannot raise the AI evidence score.
        for f in synth.get("findings", []):
            title = (f.get("title") or "").lower()
            sev = f.get("severity", "Medium")
            conf = f.get("confidence", "Medium")
            explicit_disclosure = "c2pa" in title and "disclosure" in title
            items.append({
                "family": "synthid",
                "dir": AI_INDICATOR if explicit_disclosure else NEUTRAL,
                "rel": RELIABILITY.get("synthid", 0.35),
                "sev": sev, "conf": conf, "fid": f.get("id"),
            })
    return items


def _family_totals(items: list[dict]) -> tuple[dict, dict, list[dict]]:
    ai_tot = {k: 0.0 for k in FAMILY_CAP}
    auth_tot = {k: 0.0 for k in FAMILY_CAP}
    evidence = []
    for it in items:
        w = _weight(it["sev"], it["conf"], it["rel"])
        if it["dir"] == AI_INDICATOR:
            ai_tot[it["family"]] += w
            impact = "SUPPORTING"
        elif it["dir"] == AUTHENTICITY_SUPPORT:
            auth_tot[it["family"]] += w
            impact = "OPPOSING"
        else:
            impact = "CONTEXT"
        evidence.append({
            "source": it["family"], "finding_id": it["fid"],
            "impact": impact, "weight": round(min(w, FAMILY_CAP[it["family"]]), 4),
        })
    # Apply per-family caps (double-counting protection).
    for k in FAMILY_CAP:
        ai_tot[k] = min(ai_tot[k], FAMILY_CAP[k])
        auth_tot[k] = min(auth_tot[k], FAMILY_CAP[k])
    return ai_tot, auth_tot, evidence


def assess(results: dict) -> dict:
    items = _collect(results)
    ai_tot, auth_tot, evidence = _family_totals(items)

    total_ai = sum(ai_tot.values())
    total_auth = sum(auth_tot.values())
    max_evidence = max(total_ai, total_auth)

    # Modules bookkeeping.
    modules_used, modules_unavailable = [], []
    for name in ("metadata", "c2pa", "forensics", "artifacts", "ai_detector",
                 "synthid", "jpeg_ghost", "cfa"):
        r = results.get(name)
        if r is None:
            modules_unavailable.append(name)
        else:
            modules_used.append(name)

    forensics = results.get("forensics") or {}
    capture = forensics.get("screen_capture") or {}
    style = forensics.get("content_style") or {}
    transform = forensics.get("transformation_history") or {}

    context_flags = []
    if capture.get("likely_screen_capture"):
        context_flags.append("possible_screen_capture")
    if style.get("stylized_or_illustrated"):
        context_flags.append("stylized_or_illustrated")
    if transform.get("available") and any(
            f.get("evidence_direction") == "CONTEXT"
            for f in forensics.get("findings", [])):
        context_flags.append("possible_resampling_or_smoothing")

    limitations = [
        "AI detectors can produce false positives and false negatives.",
        "Forensic heuristics (ELA, noise, frequency, residual correlation) are not definitive.",
        "Visual-artifact observations are suggestive, not conclusive.",
        "No visual-only method can reliably identify every generator or recover the source of a tightly cropped screenshot.",
    ]
    if (results.get("c2pa") or {}).get("status") == "PRESENT_UNVERIFIED":
        limitations.append("C2PA provenance was detected but not cryptographically verified.")
    if (results.get("ai_detector") or {}).get("status") == "NOT_CONFIGURED":
        limitations.append("No external AI detector was configured; it contributed no evidence.")
    if context_flags:
        limitations.append(
            "The image has transformation/style context signals. These describe the uploaded file, "
            "not the origin of the depicted artwork."
        )

    # A verified, explicit AI-generation claim is the only definitive verdict.
    # This branch intentionally precedes model disagreement: a trusted signed
    # provenance claim is stronger than an uncalibrated pixel classifier.
    verified_ai = _verified_ai_provenance(results)
    ensemble = (results.get("ai_detector") or {}).get("ensemble") or {}
    strong_ai_consensus = bool(
        ensemble.get("strong_consensus") and
        ensemble.get("ai_votes", 0) >= 2 and
        ensemble.get("consensus") in ("AI_GENERATED", "LIKELY_AI")
    )

    # --- Decision logic ---
    contradictory = total_auth >= 0.15 and total_ai >= 0.15

    if verified_ai:
        assessment = HIGH
        ai_assessment = PROVEN_AI
        confidence = "HIGH"
        evidence_score = 1.0
        verdict = PROVEN_AI
        verdict_strength = "DEFINITIVE"
        definitive = True
        proof_basis = "Cryptographically verified C2PA provenance explicitly indicates AI generation."
    elif strong_ai_consensus and not contradictory:
        assessment = HIGH
        ai_assessment = HIGH_CONFIDENCE_AI
        confidence = "HIGH"
        evidence_score = round(min(1.0, total_ai), 3)
        verdict = HIGH_CONFIDENCE_AI
        verdict_strength = "HIGH_CONFIDENCE"
        definitive = False
        proof_basis = "At least two configured local classifiers agree with high model confidence."
    elif max_evidence < 0.10:
        assessment = INSUFFICIENT
        ai_assessment = "INSUFFICIENT_EVIDENCE"
        confidence = "LOW"
        evidence_score = 0.0
        verdict = ORIGIN_UNKNOWN
        verdict_strength = "UNKNOWN"
        definitive = False
        proof_basis = "No independent AI-origin evidence passed the minimum evidence threshold."
    elif contradictory:
        assessment = INCONCLUSIVE
        ai_assessment = "INCONCLUSIVE"
        confidence = "LOW"
        evidence_score = round(min(1.0, total_ai), 3)
        verdict = INCONCLUSIVE
        verdict_strength = "CONFLICTING"
        definitive = False
        proof_basis = "AI-leaning and authenticity-leaning evidence conflict."
    else:
        evidence_score = round(min(1.0, total_ai), 3)
        if evidence_score < BAND_LOW:
            assessment = LOW
        elif evidence_score < BAND_MOD:
            assessment = MODERATE
        elif evidence_score < BAND_ELEV:
            assessment = ELEVATED
        else:
            # Reserve HIGH for verified provenance or an explicit ensemble
            # consensus. A large heuristic score is still only possible AI.
            assessment = ELEVATED
        ai_assessment = {
            LOW: "EVIDENCE_DOES_NOT_INDICATE_AI_GENERATION",
            MODERATE: "EVIDENCE_SUGGESTS_POSSIBLE_AI_GENERATION",
            ELEVATED: "POSSIBLE_AI_GENERATION",
            HIGH: "POSSIBLE_AI_GENERATION",
        }[assessment]
        # Confidence from family diversity.
        n_fam = sum(1 for k in FAMILY_CAP if ai_tot[k] > 0)
        if evidence_score >= BAND_ELEV and n_fam >= 3:
            confidence = "HIGH"
        elif n_fam >= 2:
            confidence = "MEDIUM"
        else:
            confidence = "LOW"
        verdict = ("POSSIBLE_AI_GENERATION" if total_ai >= BAND_LOW
                   else ORIGIN_UNKNOWN)
        verdict_strength = "SUGGESTIVE" if total_ai >= BAND_LOW else "UNKNOWN"
        definitive = False
        proof_basis = (
            "One or more heuristic/model evidence families are AI-leaning, but no "
            "trusted provenance or multi-model consensus establishes origin."
        )

    # --- Explanatory text ---
    ai_fams = [k for k in FAMILY_CAP if ai_tot[k] > 0]
    auth_fams = [k for k in FAMILY_CAP if auth_tot[k] > 0]
    corroboration = []
    if not contradictory and len(ai_fams) >= 2:
        corroboration.append(
            f"Independent evidence from {', '.join(ai_fams)} corroborates the assessment.")
    if contradictory:
        corroboration.append(
            "Evidence sources disagree: both AI-generation and authenticity signals are present.")

    summary = _summary(assessment, ai_assessment, ai_fams, auth_fams, contradictory)

    # Authenticity is never established by this engine. A verified AI claim is
    # different: the origin claim is proven, while the depicted content may
    # still have been edited afterward.
    origin_unknown = not verified_ai

    return {
        "status": "COMPLETE",
        "assessment": assessment,
        "evidence_score": evidence_score,
        "confidence": confidence,
        "ai_assessment": ai_assessment,
        "verdict": verdict,
        "verdict_strength": verdict_strength,
        "definitive": definitive,
        "proof_basis": proof_basis,
        "verified_ai_provenance": verified_ai,
        "ensemble_consensus": ensemble,
        "summary": summary,
        "evidence": evidence,
        "corroboration": corroboration,
        "contradictions": (["Conflicting strong evidence (AI vs authenticity)."]
                           if contradictory else []),
        "authenticity_established": False,
        "origin_unknown": origin_unknown,
        "context_flags": context_flags,
        "limitations": limitations,
        "modules_used": modules_used,
        "modules_unavailable": modules_unavailable,
    }


def _verified_ai_provenance(results: dict) -> bool:
    """Return True only for an explicit verified AI-generation claim.

    ``VERIFIED`` is deliberately not inferred from a marker scan. The current
    C2PA analyzer exposes VERIFIED only for an explicitly verified provider or
    test fixture, so this helper remains conservative if schemas evolve.
    """
    c2pa = results.get("c2pa") or {}
    if c2pa.get("status") != "VERIFIED" or c2pa.get("verified") is not True:
        return False
    findings = c2pa.get("findings", [])
    explicit = any("ai-generation provenance" in (f.get("title") or "").lower()
                   for f in findings)
    provenance = c2pa.get("provenance") or {}
    source_type = str(provenance.get("digital_source_type", "")).lower()
    return explicit or ("ai" in source_type and "generated" in source_type)


def _summary(assessment, ai_assessment, ai_fams, auth_fams, contradictory) -> str:
    if ai_assessment == PROVEN_AI:
        return ("Cryptographically verified content credentials explicitly indicate "
                "AI generation. This establishes the provenance claim for the signed "
                "asset, not that every pixel is unedited.")
    if ai_assessment == HIGH_CONFIDENCE_AI:
        return ("Multiple configured local classifiers agree that the image is likely "
                "AI-generated. This is high-confidence model agreement, not proof or "
                "a calibrated probability.")
    if assessment == INSUFFICIENT:
        return ("Insufficient independent evidence was found to support a conclusion. "
                "This does not establish that the image is authentic or AI-generated.")
    if assessment == INCONCLUSIVE:
        return ("Evidence sources conflict, so a single definitive conclusion is not "
                "supported. The assessment is inconclusive.")
    base = (f"Assessment: {assessment}. AI assessment: {ai_assessment.replace('_', ' ').lower()}."
            f" AI-leaning signals: {', '.join(ai_fams) or 'none'}."
            f" Authenticity-leaning signals: {', '.join(auth_fams) or 'none'}.")
    return base + " The available evidence is suggestive rather than conclusive."
