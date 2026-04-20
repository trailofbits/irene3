package anvill.macho

import ghidra.app.util.bin.format.objc2.ObjectiveC2_Constants
import ghidra.program.model.address.Address
import ghidra.program.model.listing.{Function, Program}
import ghidra.program.model.symbol.{RefType, Symbol, SymbolType}
import ghidra.util.Msg
import specification.specification.Symbol as SymbolSpec

import scala.util.Try

/** Objective-C metadata extractor.
 *
 *  Until the vendor/anvill proto PR lands (which adds `is_objc_method`,
 *  `objc_selector`, `arc_kind`, etc. as real fields), we encode all
 *  ObjC metadata as sentinel entries in the spec's existing
 *  `repeated Symbol symbols` field. Every sentinel name starts with
 *  `ArcRuntime.sentinelPrefix` so the downstream lifter can filter
 *  them with one `startsWith` check.
 *
 *  Sentinel name format:
 *    __irene_objc_class_<ClassName>
 *    __irene_objc_method_<address-hex>_<ClassName>::<selector>
 *    __irene_objc_selref_<address-hex>
 *    __irene_arc_<kind>_<callsite-address-hex>
 *    __irene_objc_msgsend_<variant>_<callsite-address-hex>
 *
 *  `address` on each sentinel Symbol is the address the tag applies
 *  to (class address, method entry, selref slot, or call-site
 *  instruction address).
 *
 *  This module is activated only on Mach-O programs; the `extract`
 *  entry point is a no-op otherwise.
 */
object ObjcSpecifier:

  /** Enter-once guard for the "ObjC analyser did not run" warning so
   *  it is logged at most once per specifyProgram call. */
  private val warnedOnce = new ThreadLocal[java.lang.Boolean] {
    override def initialValue: java.lang.Boolean = false
  }

  /** Walk the program and return the full set of ObjC-related
   *  sentinel symbols to append to the spec. Safe to call on any
   *  Program; returns an empty sequence if the program is not
   *  Mach-O or the ObjC analyser left no footprint.
   */
  def extract(prog: Program): Seq[SymbolSpec] =
    if !MachoDetection.isMachO(prog) then return Seq.empty
    warnedOnce.set(false)

    val classes       = extractClasses(prog)
    val methods       = extractMethods(prog)
    val selrefs       = extractSelrefs(prog)
    val arcCalls      = extractArcCallSites(prog)
    val msgSendCalls  = extractMsgSendCallSites(prog)

    // Warn exactly once per program if we saw ObjC sections but
    // recovered no classes — suggests the analyser did not run.
    if classes.isEmpty && hasObjcSections(prog) then
      warnOnce(
        prog,
        "ObjC sections present but no classes recovered; enable the " +
          "'Objective-C 2 Class' analyser and re-analyse."
      )

    classes ++ methods ++ selrefs ++ arcCalls ++ msgSendCalls

  // ------------------------------------------------------------------
  //  Classes
  // ------------------------------------------------------------------

  /** Enumerate Objective-C classes.
   *
   *  Ghidra's ObjC analyser registers each class as a `Class`-typed
   *  symbol directly under the global namespace (on this amp-ghidra
   *  build the "objc" namespace is a peer, and the class symbols
   *  live at the global level). We iterate the global children and
   *  keep `SymbolType.CLASS` entries. The class's storage lives at
   *  the `_OBJC_CLASS_$_<Name>` label; use it when available so the
   *  downstream lifter has a real address to point at.
   */
  private def extractClasses(prog: Program): Seq[SymbolSpec] =
    val symTab = prog.getSymbolTable
    val global = prog.getGlobalNamespace
    val out = scala.collection.mutable.ArrayBuffer.empty[SymbolSpec]
    val iter = symTab.getChildren(global.getSymbol)
    while iter.hasNext do
      val s = iter.next()
      if s.getSymbolType == SymbolType.CLASS then
        val name = s.getName
        val addr = classDataAddress(prog, name)
          .orElse(Option(s.getAddress).map(_.getOffset))
          .getOrElse(0L)
        out += SymbolSpec(
          name    = s"${ArcRuntime.objcClassSentinel}$name",
          address = addr
        )
    out.toSeq

  /** Look up the `_OBJC_CLASS_$_<Name>` label and return its address. */
  private def classDataAddress(prog: Program, className: String): Option[Long] =
    val label = s"_OBJC_CLASS_\\$$_$className"
    val syms = prog.getSymbolTable.getGlobalSymbols(label)
    if syms.isEmpty then None
    else Some(syms.get(0).getAddress.getOffset)

  // ------------------------------------------------------------------
  //  Methods
  // ------------------------------------------------------------------

  /** Enumerate Objective-C methods.
   *
   *  Ghidra's ObjC analyser stores each method as a Function whose
   *  parent namespace is the owning Class. We detect ObjC methods by
   *  checking `parent.getSymbolType == CLASS`, then rebuild the
   *  canonical display name `-[Class selector]` (instance) or
   *  `+[Class selector]` (class method).
   *
   *  As a fallback for binaries where Ghidra used the flat
   *  `-[Class selector]` name directly on the function, we also
   *  match that pattern via `parseObjcMethodName`.
   */
  private def extractMethods(prog: Program): Seq[SymbolSpec] =
    val fm = prog.getFunctionManager
    val iter = fm.getFunctions(true)
    val out = scala.collection.mutable.ArrayBuffer.empty[SymbolSpec]
    while iter.hasNext do
      val f = iter.next()
      val addr = f.getEntryPoint.getOffset
      methodFromNamespace(f) match
        case Some((kind, cls, sel)) =>
          out += SymbolSpec(
            name    = s"${ArcRuntime.objcMethodSentinel}${addr.toHexString}_${kind}[$cls $sel]",
            address = addr
          )
        case None =>
          parseObjcMethodName(f.getName) match
            case Some((kind, cls, sel)) =>
              out += SymbolSpec(
                name    = s"${ArcRuntime.objcMethodSentinel}${addr.toHexString}_${kind}[$cls $sel]",
                address = addr
              )
            case None => ()
    out.toSeq

  /** If the function's parent namespace is an ObjC Class, return
   *  (kind, class, selector). Infer `kind` as `+` when the function
   *  name starts with `+` or is nested in a metaclass; else `-`.
   */
  private def methodFromNamespace(f: Function): Option[(String, String, String)] =
    val parent = f.getParentNamespace
    Option(parent).filter(ns =>
      Option(ns.getSymbol).exists(_.getSymbolType == SymbolType.CLASS)
    ).map { ns =>
      val cls = ns.getName
      val rawSel = f.getName
      // Ghidra sometimes prefixes the selector with +/-. Strip and
      // record the kind.
      val (kind, sel) =
        if rawSel.startsWith("+") then ("+", rawSel.drop(1))
        else if rawSel.startsWith("-") then ("-", rawSel.drop(1))
        else ("-", rawSel)
      (kind, cls, sel)
    }

  /** Parse a Ghidra function name of the form `-[Class sel:]` or
   *  `+[Class sel:]` into (kind, class, selector) where `kind` is
   *  `"-"` (instance) or `"+"` (class).
   */
  def parseObjcMethodName(name: String): Option[(String, String, String)] =
    val trimmed = name.trim
    if (trimmed.startsWith("-[") || trimmed.startsWith("+[")) &&
       trimmed.endsWith("]") then
      val kind = trimmed.charAt(0).toString
      val inner = trimmed.substring(2, trimmed.length - 1)
      val spaceIdx = inner.indexOf(' ')
      if spaceIdx > 0 && spaceIdx + 1 < inner.length then
        Some((kind, inner.substring(0, spaceIdx), inner.substring(spaceIdx + 1)))
      else None
    else None

  // ------------------------------------------------------------------
  //  Selrefs
  // ------------------------------------------------------------------

  /** Emit a sentinel at every address in the `__objc_selrefs` block.
   *  The downstream lifter can follow each slot to the selector
   *  string. Safe fallback when the lifter doesn't yet know to parse
   *  selrefs: a plain sentinel list still tells it which call sites
   *  reference selectors.
   */
  private def extractSelrefs(prog: Program): Seq[SymbolSpec] =
    val block = Option(prog.getMemory.getBlock(ObjectiveC2_Constants.OBJC2_SELECTOR_REFS))
      .getOrElse(return Seq.empty)
    val out = scala.collection.mutable.ArrayBuffer.empty[SymbolSpec]
    val start = block.getStart.getOffset
    val end = block.getEnd.getOffset
    // selrefs are pointer-sized; 8 bytes on arm64/x86_64.
    val step = prog.getDefaultPointerSize
    var addr = start
    while addr <= end && addr + step - 1 <= end do
      out += SymbolSpec(
        name    = s"${ArcRuntime.objcSelrefSentinel}${addr.toHexString}",
        address = addr
      )
      addr += step
    out.toSeq

  // ------------------------------------------------------------------
  //  ARC + msgSend call-sites
  // ------------------------------------------------------------------

  private def extractArcCallSites(prog: Program): Seq[SymbolSpec] =
    callSiteSentinels(prog, ArcRuntime.objcArcSymbols, ArcRuntime.objcArcSentinel)

  private def extractMsgSendCallSites(prog: Program): Seq[SymbolSpec] =
    callSiteSentinels(prog, ArcRuntime.objcMsgSendFamily, ArcRuntime.objcMsgSendSentinel)

  /** Walk every function and emit a sentinel at each call site whose
   *  (thunk-chased) target name is in `targets`.
   */
  private def callSiteSentinels(
      prog: Program,
      targets: Map[String, String],
      prefix: String,
  ): Seq[SymbolSpec] =
    val fm = prog.getFunctionManager
    val iter = fm.getFunctions(true)
    val out = scala.collection.mutable.ArrayBuffer.empty[SymbolSpec]
    while iter.hasNext do
      val f = iter.next()
      collectFunctionCalls(prog, f, targets, prefix, out)
    out.toSeq

  private def collectFunctionCalls(
      prog: Program,
      func: Function,
      targets: Map[String, String],
      prefix: String,
      out: scala.collection.mutable.ArrayBuffer[SymbolSpec],
  ): Unit =
    val listing = prog.getListing
    val instrIter = listing.getInstructions(func.getBody, true)
    while instrIter.hasNext do
      val instr = instrIter.next()
      val flow = instr.getFlowType
      if flow.isCall then
        resolveCallTargetName(prog, instr.getAddress) match
          case Some(name) =>
            targets.get(name) match
              case Some(tag) =>
                val callAddr = instr.getAddress.getOffset
                out += SymbolSpec(
                  name    = s"$prefix${tag}_${callAddr.toHexString}",
                  address = callAddr
                )
              case None => ()
          case None => ()

  /** Resolve the name of the called symbol at `callAddr`, chasing one
   *  level of thunk. Returns `None` if the call target isn't a known
   *  Function or Symbol.
   */
  private def resolveCallTargetName(prog: Program, callAddr: Address): Option[String] =
    val refs = prog.getReferenceManager.getReferencesFrom(callAddr)
    refs.find(r => r.getReferenceType.isCall) match
      case Some(ref) =>
        val target = ref.getToAddress
        val fm = prog.getFunctionManager
        Option(fm.getFunctionAt(target)) match
          case Some(f) =>
            val real = if f.isThunk then f.getThunkedFunction(true) else f
            Some(real.getName)
          case None =>
            // No function at target — maybe an external symbol.
            Option(prog.getSymbolTable.getPrimarySymbol(target)).map(_.getName)
      case None => None

  // ------------------------------------------------------------------
  //  Namespaces / sections
  // ------------------------------------------------------------------

  /** True if the binary carries any `__objc_*` section (informs
   *  whether to emit a missing-analyser warning).
   */
  private def hasObjcSections(prog: Program): Boolean =
    val mem = prog.getMemory
    ObjectiveC2_Constants.getObjectiveC2SectionNames
      .iterator()
      .hasNext // non-empty list
    && {
      val names = ObjectiveC2_Constants.getObjectiveC2SectionNames
      val it = names.iterator()
      var found = false
      while it.hasNext && !found do
        if mem.getBlock(it.next()) != null then found = true
      found
    }

  private def warnOnce(prog: Program, msg: String): Unit =
    if !warnedOnce.get() then
      warnedOnce.set(true)
      Msg.warn(this, s"[objc] ${prog.getName}: $msg")
