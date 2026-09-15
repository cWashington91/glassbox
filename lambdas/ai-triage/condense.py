"""Condenses a Stage 1 Ghidra report into a bounded payload worth sending
to a model.

Stage 1 reports can be huge -- a real stress-test binary produced a 26MB
report. This picks the subset that's actually useful for triage: full
import/section data (already small regardless of binary size), a bounded
sample of strings, aggregate control-flow stats, and the N largest
functions Stage 1 already decompiled. That last part deliberately reuses
Stage 1's own largest-first decompile-budget ordering rather than
inventing a new selection heuristic here.
"""

MAX_TRIAGE_STRINGS = 150
MAX_TRIAGE_IMPORT_SYMBOLS = 300
TOP_N_DECOMPILED_FUNCTIONS = 15
MAX_FUNCTION_CODE_CHARS = 4000


def condense_report(report: dict) -> dict:
    functions = report.get("functions", [])
    decompiled = [f for f in functions if f.get("decompiled")]
    decompiled.sort(key=lambda f: f.get("byte_size", 0), reverse=True)
    selected = decompiled[:TOP_N_DECOMPILED_FUNCTIONS]

    imports = report.get("imports", {"libraries": [], "symbols": []})
    symbols = imports.get("symbols", [])

    strings = report.get("strings", {"items": [], "total_count": 0})
    string_items = strings.get("items", [])

    cfg_summary = report.get("control_flow_summary", {})
    total_decompiled = cfg_summary.get("decompiled_function_count", len(decompiled))

    return {
        "program": report.get("program", {}),
        # Partial analysis/metadata is a real possibility on a large or
        # complex binary (see extract.py) -- the model needs this to
        # avoid overconfident claims about a binary it only saw part of.
        "analysis_status": report.get("analysis_status", {}),
        "control_flow_summary": cfg_summary,
        "sections": report.get("sections", []),
        "imports": {
            "libraries": imports.get("libraries", []),
            "symbols": symbols[:MAX_TRIAGE_IMPORT_SYMBOLS],
            "symbols_truncated": len(symbols) > MAX_TRIAGE_IMPORT_SYMBOLS,
            "symbol_total_count": len(symbols),
        },
        "strings": {
            "items": string_items[:MAX_TRIAGE_STRINGS],
            "sample_truncated": len(string_items) > MAX_TRIAGE_STRINGS,
            "total_count": strings.get("total_count", len(string_items)),
        },
        "decompiled_functions": [_condense_function(f) for f in selected],
        "decompiled_functions_note": (
            f"Showing the {len(selected)} largest of {total_decompiled} "
            "functions Stage 1 successfully decompiled (prioritized "
            "largest-first within its own time budget). This is not "
            "every function in the binary -- see control_flow_summary "
            "for the true function_count."
        ),
    }


def _condense_function(f: dict) -> dict:
    code = f.get("decompiled_code") or ""
    return {
        "name": f["name"],
        "entry_point": f["entry_point"],
        "signature": f["signature"],
        "indirect_transfer_count": f["indirect_transfer_count"],
        "calls": f["calls"],
        "decompiled_code": code[:MAX_FUNCTION_CODE_CHARS],
        "decompiled_code_truncated": len(code) > MAX_FUNCTION_CODE_CHARS,
    }
