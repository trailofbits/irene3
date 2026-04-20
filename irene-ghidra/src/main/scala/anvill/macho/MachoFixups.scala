package anvill.macho

import ghidra.program.model.listing.Program
import ghidra.util.Msg

/** Sanity checks for Mach-O loader metadata Ghidra is expected to have
 *  resolved before we run spec extraction.
 *
 *  The only check today is for `LC_DYLD_CHAINED_FIXUPS` — on binaries
 *  built for iOS 15+ and recent macOS releases, imports are recorded
 *  in the chained-fixup stream instead of classic `LC_DYLD_INFO_ONLY`
 *  tables. Older Ghidra versions (< 10.3) do not parse chained fixups,
 *  so the program's external symbol table ends up empty and the spec
 *  extractor silently emits stub calls with no callee information.
 *
 *  We emit a single clear warning rather than throwing because:
 *    1. Some legitimate test binaries have few or zero external calls.
 *    2. A missing bind does not corrupt the rest of the spec —
 *       only external call-site targets are affected.
 *  The warning directs the user to upgrade Ghidra.
 */
object MachoFixups:

  @volatile private var alreadyWarned: Boolean = false

  /** Log a one-shot diagnostic if the program uses chained fixups but
   *  Ghidra did not populate any external symbols.
   *  No-op on binaries that do not use chained fixups, or on fixtures
   *  that legitimately have no imports.
   */
  def verifyExternalsResolved(prog: Program): Unit =
    if MachoHeaderReader.usesChainedFixups(prog) then
      val iter = prog.getSymbolTable.getExternalSymbols
      var externalCount = 0
      while iter.hasNext do
        iter.next()
        externalCount += 1
      if externalCount == 0 then warnOnce(prog)

  private def warnOnce(prog: Program): Unit =
    synchronized {
      if !alreadyWarned then
        alreadyWarned = true
        Msg.warn(
          this,
          s"[macho] ${prog.getName} uses LC_DYLD_CHAINED_FIXUPS but Ghidra " +
            "resolved 0 external symbols. This usually means Ghidra < 10.3 " +
            "is in use; external call targets will be missing from the " +
            "spec. Upgrade to Ghidra >= 10.3 for chained-fixup support."
        )
    }
