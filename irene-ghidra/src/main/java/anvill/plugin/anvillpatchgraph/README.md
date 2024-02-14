# `AnvillGraphPlugin`

This Ghidra plugin closely follows a lot of what's done in Ghidra's own `FunctionGraphPlugin`,
however the functionality is much more limited to hopefully provide only the minimal functionality
that is required.

The license of Ghidra code is Apache 2.0 (http://www.apache.org/licenses/LICENSE-2.0), and the files
that are based on upstream contain the appropriate license header.

The primary file/class is `AnvillGraphProvider` where the graph is built and display controlled.
This class implements functionality from other classes that would otherwise be mirrored from the
upstream plugin.
