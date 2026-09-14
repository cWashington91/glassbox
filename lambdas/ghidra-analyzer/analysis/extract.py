"""Static extraction of a structured report from a binary, via PyGhidra.

Drives Ghidra's headless analysis natively from Python (no analyzeHeadless
subprocess, no on-disk Ghidra project -- see ghidra_scripts/ history for
why). Produces the raw, mechanical report that Stage 2 (the AI triage
Lambda) interprets. This module deliberately does not judge anything as
"suspicious" -- it only extracts facts.
"""

import time

import pyghidra

MIN_STRING_LENGTH = 4
MAX_STRINGS = 2000
MAX_STRING_LENGTH = 500
MAX_CALL_EDGES = 25
DEFAULT_ANALYSIS_BUDGET_SECONDS = 180.0
DEFAULT_METADATA_BUDGET_SECONDS = 60.0
DEFAULT_DECOMPILE_BUDGET_SECONDS = 60.0
PER_FUNCTION_DECOMPILE_TIMEOUT_SECONDS = 30

# A real 26MB shared library (libjvm.so) produced 50,000+ functions from
# symbol data alone, before any analysis ran -- full auto-analysis on that
# didn't finish in 280s. Every unbounded, binary-size-scaling phase here
# (Ghidra's own auto-analysis, our per-function metadata walk, and
# decompilation) gets its own wall-clock budget so a large/complex binary
# degrades to a partial-but-honest report instead of running until Lambda
# kills the process with nothing written back to S3.


def analyze_binary(
    binary_path: str,
    analysis_budget_seconds: float = DEFAULT_ANALYSIS_BUDGET_SECONDS,
    metadata_budget_seconds: float = DEFAULT_METADATA_BUDGET_SECONDS,
    decompile_budget_seconds: float = DEFAULT_DECOMPILE_BUDGET_SECONDS,
) -> dict:
    if not pyghidra.started():
        pyghidra.start(verbose=False)

    from ghidra.app.util.importer import ProgramLoader

    with ProgramLoader.builder().source(binary_path).load() as load_results:
        program = load_results.getPrimaryDomainObject()

        # NOTE: pyghidra.analyze() unconditionally cancels its monitor as
        # part of its own cleanup once startAnalysis() returns, whether
        # that's because analysis finished or because our timeout fired --
        # so monitor.isCancelled() can't tell those two cases apart
        # (verified empirically: a 2.7s analysis against a 180s budget
        # still reports isCancelled() == True afterward). Elapsed wall
        # time vs. the requested budget is the only reliable signal here.
        analysis_monitor = pyghidra.task_monitor(timeout=int(analysis_budget_seconds))
        analysis_start = time.monotonic()
        pyghidra.analyze(program, monitor=analysis_monitor)
        analysis_complete = (time.monotonic() - analysis_start) < analysis_budget_seconds

        functions, cfg_summary, metadata_complete = _extract_functions_and_cfg(
            program, metadata_budget_seconds, decompile_budget_seconds
        )

        return {
            "program": {
                "name": program.getName(),
                "language": str(program.getLanguageID()),
                "compiler_spec": str(program.getCompilerSpec().getCompilerSpecID()),
                "image_base": hex(program.getImageBase().getOffset()),
                "executable_format": program.getExecutableFormat(),
            },
            "analysis_status": {
                "analysis_complete": analysis_complete,
                "analysis_budget_seconds": analysis_budget_seconds,
                "metadata_complete": metadata_complete,
                "metadata_budget_seconds": metadata_budget_seconds,
            },
            "sections": _extract_sections(program),
            "imports": _extract_imports(program),
            "strings": _extract_strings(program),
            "functions": functions,
            "control_flow_summary": cfg_summary,
        }


def _extract_sections(program) -> list:
    sections = []
    for block in program.getMemory().getBlocks():
        sections.append({
            "name": block.getName(),
            "start": hex(block.getStart().getOffset()),
            "size": block.getSize(),
            "executable": bool(block.isExecute()),
            "writable": bool(block.isWrite()),
        })
    return sections


def _extract_imports(program) -> dict:
    ext_mgr = program.getExternalManager()
    libraries = [str(name) for name in ext_mgr.getExternalLibraryNames() if str(name) != "<EXTERNAL>"]

    symbols = []
    for sym in program.getSymbolTable().getExternalSymbols():
        symbols.append({
            "name": sym.getName(),
            "library": sym.getParentNamespace().getName(),
        })

    return {"libraries": libraries, "symbols": symbols}


def _extract_strings(program) -> dict:
    items = []
    total_count = 0
    for data in program.getListing().getDefinedData(True):
        if not data.hasStringValue():
            continue
        total_count += 1
        if len(items) >= MAX_STRINGS:
            continue
        try:
            value = str(data.getValue())
        except Exception:
            continue
        if len(value) < MIN_STRING_LENGTH:
            continue
        truncated = len(value) > MAX_STRING_LENGTH
        items.append({
            "address": hex(data.getAddress().getOffset()),
            "value": value[:MAX_STRING_LENGTH],
            "truncated": truncated,
        })

    return {
        "items": items,
        "total_count": total_count,
        "list_truncated": total_count > len(items),
    }


def _is_indirect_transfer(instruction) -> bool:
    flow_type = instruction.getFlowType()
    return bool(flow_type.isComputed() and (flow_type.isCall() or flow_type.isJump()))


def _extract_functions_and_cfg(program, metadata_budget_seconds: float, decompile_budget_seconds: float):
    fm = program.getFunctionManager()

    # Cheap pass: every function gets these fields regardless of size,
    # since they come straight off the FunctionManager with no
    # instruction-level walking.
    raw_functions = list(fm.getFunctions(True))
    entries = []
    for f in raw_functions:
        entries.append({
            "name": f.getName(),
            "entry_point": hex(f.getEntryPoint().getOffset()),
            "signature": f.getSignature().getPrototypeString(),
            "calling_convention": f.getCallingConventionName(),
            "is_thunk": bool(f.isThunk()),
            "is_external": bool(f.isExternal()),
            "byte_size": f.getBody().getNumAddresses(),
            "basic_block_count": None,
            "indirect_transfer_count": None,
            "calls": [],
            "calls_truncated": False,
            "called_by": [],
            "called_by_truncated": False,
            "decompiled": False,
            "decompiled_code": None,
        })

    metadata_complete = _fill_metadata_within_budget(
        program, raw_functions, entries, metadata_budget_seconds
    )
    _decompile_within_budget(program, raw_functions, entries, decompile_budget_seconds)

    total_basic_blocks = sum(e["basic_block_count"] or 0 for e in entries)
    total_indirect_transfers = sum(e["indirect_transfer_count"] or 0 for e in entries)
    decompiled_count = sum(1 for e in entries if e["decompiled"])
    cfg_summary = {
        "function_count": len(entries),
        "functions_with_full_metadata": sum(1 for e in entries if e["basic_block_count"] is not None),
        "basic_block_count": total_basic_blocks,
        "indirect_transfer_count": total_indirect_transfers,
        "decompiled_function_count": decompiled_count,
        "decompile_budget_seconds": decompile_budget_seconds,
    }
    return entries, cfg_summary, metadata_complete


def _fill_metadata_within_budget(program, raw_functions, entries, budget_seconds: float) -> bool:
    """Fills basic-block/indirect-transfer/call-graph fields, largest functions
    first, until the time budget runs out. Returns whether every function
    was covered."""
    from ghidra.program.model.block import BasicBlockModel
    from ghidra.util.task import ConsoleTaskMonitor

    listing = program.getListing()
    monitor = ConsoleTaskMonitor()
    bbm = BasicBlockModel(program)

    order = sorted(range(len(entries)), key=lambda i: entries[i]["byte_size"], reverse=True)
    deadline = time.monotonic() + budget_seconds

    for idx in order:
        if time.monotonic() >= deadline:
            return False
        f = raw_functions[idx]
        body = f.getBody()
        basic_block_count = len(list(bbm.getCodeBlocksContaining(body, monitor)))
        indirect_count = sum(
            1 for instr in listing.getInstructions(body, True) if _is_indirect_transfer(instr)
        )
        calls = [c.getName() for c in f.getCalledFunctions(monitor)]
        called_by = [c.getName() for c in f.getCallingFunctions(monitor)]

        entry = entries[idx]
        entry["basic_block_count"] = basic_block_count
        entry["indirect_transfer_count"] = indirect_count
        entry["calls"] = calls[:MAX_CALL_EDGES]
        entry["calls_truncated"] = len(calls) > MAX_CALL_EDGES
        entry["called_by"] = called_by[:MAX_CALL_EDGES]
        entry["called_by_truncated"] = len(called_by) > MAX_CALL_EDGES

    return True


def _decompile_within_budget(program, raw_functions, entries, budget_seconds: float):
    from ghidra.app.decompiler import DecompInterface
    from ghidra.util.task import ConsoleTaskMonitor

    # Largest-first: on a big/complex binary we won't get to every function
    # within the time budget, so spend it on the functions most likely to
    # matter rather than whatever order Ghidra happened to enumerate them in.
    order = sorted(range(len(entries)), key=lambda i: entries[i]["byte_size"], reverse=True)

    ifc = DecompInterface()
    ifc.openProgram(program)
    monitor = ConsoleTaskMonitor()

    deadline = time.monotonic() + budget_seconds
    for idx in order:
        if time.monotonic() >= deadline:
            break
        function = raw_functions[idx]
        if function.isThunk() or function.isExternal():
            continue
        try:
            result = ifc.decompileFunction(function, PER_FUNCTION_DECOMPILE_TIMEOUT_SECONDS, monitor)
        except Exception:
            continue
        if result.decompileCompleted():
            entries[idx]["decompiled"] = True
            entries[idx]["decompiled_code"] = result.getDecompiledFunction().getC()
