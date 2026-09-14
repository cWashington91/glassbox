import json
import sys

import pyghidra

pyghidra.start(verbose=True)

from ghidra.app.util.importer import ProgramLoader

binary_path = sys.argv[1]

with ProgramLoader.builder().source(binary_path).load() as load_results:
    program = load_results.getPrimaryDomainObject()
    analysis_log = pyghidra.analyze(program)
    funcs = [f.getName() for f in program.getFunctionManager().getFunctions(True)]
    result = {
        "name": program.getName(),
        "language": str(program.getLanguageID()),
        "function_count": program.getFunctionManager().getFunctionCount(),
        "sample_functions": funcs[:10],
    }
    print("RESULT_JSON:" + json.dumps(result))
