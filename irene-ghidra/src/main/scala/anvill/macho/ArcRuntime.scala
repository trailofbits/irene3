package anvill.macho

/** Hard-coded runtime-symbol tables that the ObjC and Swift specifiers
 *  use to classify call sites. Extracted into its own module so the
 *  lists can be audited without touching extraction logic.
 *
 *  Strings are kept here (instead of an enum) because:
 *   - the downstream consumers (irene3 C++ lifter) read them from the
 *     emitted Symbol name prefix, not from any proto enum, until the
 *     vendor/anvill proto PR lands and promotes them to fields.
 *   - the set evolves across compiler versions (new ARC helpers get
 *     added) — a string table is easier to extend than a proto enum.
 *
 *  All symbol names are written with the leading underscore that
 *  Ghidra reports on Mach-O external symbols (C-level `objc_retain`
 *  is exposed as `_objc_retain` in the symbol table).
 */
object ArcRuntime:

  /** Objective-C ARC helpers. Value is the short arc-kind tag that
   *  gets baked into the emitted Symbol name.
   */
  val objcArcSymbols: Map[String, String] = Map(
    "_objc_retain"                            -> "retain",
    "_objc_release"                           -> "release",
    "_objc_autorelease"                       -> "autorelease",
    "_objc_retainAutorelease"                 -> "retain_autorelease",
    "_objc_retainAutoreleasedReturnValue"     -> "retain_autoreleased_return",
    "_objc_unsafeClaimAutoreleasedReturnValue"
                                              -> "unsafe_claim_return",
    "_objc_autoreleaseReturnValue"            -> "autorelease_return",
    "_objc_storeStrong"                       -> "store_strong",
    "_objc_retainBlock"                       -> "retain_block",
    "_Block_copy"                             -> "block_copy",
    "_Block_release"                          -> "block_release",
    "_objc_loadWeak"                          -> "weak_load",
    "_objc_loadWeakRetained"                  -> "weak_load_retained",
    "_objc_storeWeak"                         -> "weak_store",
    "_objc_destroyWeak"                       -> "weak_destroy",
    "_objc_copyWeak"                          -> "weak_copy",
    "_objc_moveWeak"                          -> "weak_move",
    "_objc_initWeak"                          -> "weak_init",
  )

  /** `objc_msgSend` family → canonical variant tag. */
  val objcMsgSendFamily: Map[String, String] = Map(
    "_objc_msgSend"                 -> "msgsend",
    "_objc_msgSendSuper"            -> "msgsend_super",
    "_objc_msgSend_stret"           -> "msgsend_stret",
    "_objc_msgSendSuper_stret"      -> "msgsend_super_stret",
    "_objc_msgSend_fpret"           -> "msgsend_fpret",
  )

  /** Swift ARC helpers (consumed in Phase 5). Listed here so both
   *  ObjC and Swift specifiers share a single source of truth.
   */
  val swiftArcSymbols: Map[String, String] = Map(
    "_swift_retain"                 -> "swift_retain",
    "_swift_retain_n"               -> "swift_retain_n",
    "_swift_release"                -> "swift_release",
    "_swift_release_n"              -> "swift_release_n",
    "_swift_tryRetain"              -> "swift_try_retain",
    "_swift_allocObject"            -> "swift_alloc",
    "_swift_deallocObject"          -> "swift_dealloc",
    "_swift_bridgeObjectRetain"     -> "swift_bridge_retain",
    "_swift_bridgeObjectRelease"    -> "swift_bridge_release",
    "_swift_unknownObjectRetain"    -> "swift_unknown_retain",
    "_swift_unknownObjectRelease"   -> "swift_unknown_release",
    "_swift_weakInit"               -> "swift_weak_init",
    "_swift_weakDestroy"            -> "swift_weak_destroy",
    "_swift_weakCopyInit"           -> "swift_weak_copy_init",
    "_swift_weakTakeInit"           -> "swift_weak_take_init",
    "_swift_weakLoadStrong"         -> "swift_weak_load_strong",
    "_swift_weakTakeStrong"         -> "swift_weak_take_strong",
    "_swift_weakAssign"             -> "swift_weak_assign",
  )

  /** Symbol-name prefix for every sentinel Symbol the Apple specifier
   *  emits. The downstream lifter can filter `symbol.name.startsWith`.
   */
  val sentinelPrefix: String = "__irene_"

  val objcClassSentinel: String   = s"${sentinelPrefix}objc_class_"
  val objcMethodSentinel: String  = s"${sentinelPrefix}objc_method_"
  val objcSelrefSentinel: String  = s"${sentinelPrefix}objc_selref_"
  val objcArcSentinel: String     = s"${sentinelPrefix}arc_"
  val objcMsgSendSentinel: String = s"${sentinelPrefix}objc_msgsend_"
