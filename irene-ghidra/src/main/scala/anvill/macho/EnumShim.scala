package anvill.macho

import ghidra.util.Msg
import specification.specification.CallingConvention as AnvillCC
import specification.specification.OS as AnvillOS
import specification.specification.Arch as AnvillArch

/** Indirection layer between intended (future) anvill spec enum values
 *  and the values that are actually present in the currently-vendored
 *  `vendor/anvill/data_specifications/specification.proto`.
 *
 *  The plan (see Phase 2) adds `OS_IOS`/`OS_TVOS`/`OS_WATCHOS`,
 *  `ARCH_AARCH64E`, and a set of Apple-specific calling conventions.
 *  Until those land upstream, this shim folds the new values to the
 *  nearest existing enum member and logs a one-line warning per
 *  fallback. Once the proto PR merges the shim collapses to a direct
 *  identity mapping and the log warnings disappear.
 *
 *  The shim is intentionally the only place in the extension that
 *  references these candidate-but-not-yet-present proto values by
 *  name (as strings), so that the Scala compiler does not reject the
 *  project when they are genuinely absent.
 */
object EnumShim:

  // ------------------------------------------------------------------
  //  OS
  // ------------------------------------------------------------------

  /** Returns the anvill OS enum value for an Apple platform, falling
   *  back to `OS_MACOS` (with a warning) when the proto does not yet
   *  expose `OS_IOS` / `OS_TVOS` / `OS_WATCHOS`.
   */
  def osForApplePlatform(p: MachoPlatform): AnvillOS =
    p match
      case MachoPlatform.MACOS | MachoPlatform.MAC_CATALYST =>
        AnvillOS.OS_MACOS
      case MachoPlatform.IOS | MachoPlatform.IOS_SIMULATOR =>
        tryResolveOs("OS_IOS").getOrElse {
          fallbackOsWarning("OS_IOS", AnvillOS.OS_MACOS)
          AnvillOS.OS_MACOS
        }
      case MachoPlatform.TVOS | MachoPlatform.TVOS_SIMULATOR =>
        tryResolveOs("OS_TVOS").getOrElse {
          fallbackOsWarning("OS_TVOS", AnvillOS.OS_MACOS)
          AnvillOS.OS_MACOS
        }
      case MachoPlatform.WATCHOS | MachoPlatform.WATCHOS_SIMULATOR =>
        tryResolveOs("OS_WATCHOS").getOrElse {
          fallbackOsWarning("OS_WATCHOS", AnvillOS.OS_MACOS)
          AnvillOS.OS_MACOS
        }
      case MachoPlatform.BRIDGE_OS | MachoPlatform.DRIVER_KIT |
          MachoPlatform.VISION_OS =>
        // No dedicated enum; fall back to MACOS.
        fallbackOsWarning(s"OS_<$p>", AnvillOS.OS_MACOS)
        AnvillOS.OS_MACOS
      case MachoPlatform.UNKNOWN =>
        AnvillOS.OS_MACOS

  // ------------------------------------------------------------------
  //  Arch
  // ------------------------------------------------------------------

  /** Returns `ARCH_AARCH64E` if the proto supports it; else
   *  `ARCH_AARCH64` with a warning. The caller may also set a
   *  per-function `uses_pac` flag once that field exists in the proto.
   */
  def archForArm64e(): AnvillArch =
    tryResolveArch("ARCH_AARCH64E").getOrElse {
      fallbackArchWarning("ARCH_AARCH64E", AnvillArch.ARCH_AARCH64)
      AnvillArch.ARCH_AARCH64
    }

  // ------------------------------------------------------------------
  //  Calling conventions
  // ------------------------------------------------------------------

  /** AArch64 Darwin (AAPCS64 with Darwin-specific variadic rule). */
  def ccAArch64Darwin(): AnvillCC =
    tryResolveCc("CALLING_CONVENTION_AARCH64_DARWIN").getOrElse {
      fallbackCcWarning("CALLING_CONVENTION_AARCH64_DARWIN", AnvillCC.CALLING_CONVENTION_CDECL)
      AnvillCC.CALLING_CONVENTION_CDECL
    }

  def ccObjcMsgSend(): AnvillCC =
    tryResolveCc("CALLING_CONVENTION_OBJC_MSGSEND").getOrElse {
      fallbackCcWarning("CALLING_CONVENTION_OBJC_MSGSEND", ccAArch64Darwin())
      ccAArch64Darwin()
    }

  def ccObjcMsgSendStret(): AnvillCC =
    tryResolveCc("CALLING_CONVENTION_OBJC_MSGSEND_STRET").getOrElse {
      fallbackCcWarning("CALLING_CONVENTION_OBJC_MSGSEND_STRET", ccObjcMsgSend())
      ccObjcMsgSend()
    }

  def ccObjcMsgSendFpret(): AnvillCC =
    tryResolveCc("CALLING_CONVENTION_OBJC_MSGSEND_FPRET").getOrElse {
      fallbackCcWarning("CALLING_CONVENTION_OBJC_MSGSEND_FPRET", ccObjcMsgSend())
      ccObjcMsgSend()
    }

  def ccSwiftcall(): AnvillCC =
    tryResolveCc("CALLING_CONVENTION_SWIFTCALL").getOrElse {
      fallbackCcWarning("CALLING_CONVENTION_SWIFTCALL", ccAArch64Darwin())
      ccAArch64Darwin()
    }

  def ccSwiftasynccall(): AnvillCC =
    tryResolveCc("CALLING_CONVENTION_SWIFTASYNCCALL").getOrElse {
      fallbackCcWarning("CALLING_CONVENTION_SWIFTASYNCCALL", ccSwiftcall())
      ccSwiftcall()
    }

  // ------------------------------------------------------------------
  //  Reflection helpers
  // ------------------------------------------------------------------

  private def tryResolveOs(name: String): Option[AnvillOS] =
    resolveEnum[AnvillOS](AnvillOS.getClass, name)

  private def tryResolveArch(name: String): Option[AnvillArch] =
    resolveEnum[AnvillArch](AnvillArch.getClass, name)

  private def tryResolveCc(name: String): Option[AnvillCC] =
    resolveEnum[AnvillCC](AnvillCC.getClass, name)

  /** Use Java reflection rather than direct reference so the project
   *  compiles against an anvill proto that does not yet expose these
   *  enum values. Once the proto PR lands, the helpers above can be
   *  replaced with direct references and this reflective lookup will
   *  always succeed.
   */
  private def resolveEnum[T](companion: Class[?], name: String): Option[T] =
    Option(
      try companion.getDeclaredField(name).get(null).asInstanceOf[T]
      catch case _: NoSuchFieldException => null.asInstanceOf[T]
    )

  // ------------------------------------------------------------------
  //  Warnings
  // ------------------------------------------------------------------

  @volatile private var warned: Set[String] = Set.empty

  private def warnOnce(key: String, message: String): Unit =
    synchronized {
      if !warned.contains(key) then
        warned += key
        Msg.warn(this, message)
    }

  private def fallbackOsWarning(missing: String, fallback: AnvillOS): Unit =
    warnOnce(
      s"os:$missing",
      s"[macho] vendored anvill proto lacks $missing; falling back to $fallback"
    )

  private def fallbackArchWarning(missing: String, fallback: AnvillArch): Unit =
    warnOnce(
      s"arch:$missing",
      s"[macho] vendored anvill proto lacks $missing; falling back to $fallback"
    )

  private def fallbackCcWarning(missing: String, fallback: AnvillCC): Unit =
    warnOnce(
      s"cc:$missing",
      s"[macho] vendored anvill proto lacks $missing; falling back to $fallback"
    )
