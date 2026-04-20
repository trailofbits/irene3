package anvill.macho

import ghidra.app.util.bin.MemoryByteProvider
import ghidra.app.util.bin.format.macho.MachHeader
import ghidra.app.util.bin.format.macho.commands.{
  BuildVersionCommand,
  EncryptedInformationCommand,
  LoadCommand,
  LoadCommandTypes,
  VersionMinCommand
}
import ghidra.program.model.listing.Program
import ghidra.util.Msg

import scala.jdk.CollectionConverters.*
import scala.util.{Failure, Success, Try}

/** Thrown when spec extraction refuses to proceed because the binary's
 *  __TEXT is FairPlay-encrypted (LC_ENCRYPTION_INFO.cryptid != 0).
 */
final class MachoEncryptedException(val cryptid: Int)
    extends RuntimeException(
      s"Binary is FairPlay-encrypted (cryptid = $cryptid); cannot extract " +
        "spec from encrypted __TEXT. Supply a decrypted binary."
    )

/** Reads Apple-specific metadata from an already-loaded Ghidra Program by
 *  re-parsing its in-memory Mach-O header via Ghidra's
 *  `MachHeader` / `LoadCommand` infrastructure.
 *
 *  Callers that only need the boolean predicates should prefer those
 *  (`isArm64e`, `isEncrypted`, `usesChainedFixups`) over `header`, which
 *  does a full parse. Results are not cached — parsing is cheap for the
 *  sizes typical of iOS binaries, but tight loops should memoise.
 */
object MachoHeaderReader:

  private val CPU_SUBTYPE_MASK: Int = 0x00FFFFFF
  private val CPU_SUBTYPE_ARM64E: Int = 2

  /** Parse the Mach-O header out of the program's default memory image.
   *  Returns `None` if the binary does not look like a Mach-O or the
   *  header cannot be located (e.g. file type unsupported by Ghidra's
   *  parser, or memory layout that places `__PAGEZERO` before the
   *  header).
   */
  def header(prog: Program): Option[MachHeader] =
    if !MachoDetection.isMachO(prog) then None
    else
      Try {
        val provider = MemoryByteProvider.createProgramHeaderByteProvider(prog, false)
        val h = new MachHeader(provider)
        h.parse()
        h
      } match
        case Success(h) => Some(h)
        case Failure(ex) =>
          Msg.warn(this, s"[macho] failed to parse header: ${ex.getMessage}")
          None

  /** Derive the concrete Apple platform from LC_BUILD_VERSION (preferred,
   *  introduced in 2018) or from the older LC_VERSION_MIN_* family.
   */
  def platform(prog: Program): MachoPlatform =
    header(prog) match
      case None => MachoPlatform.UNKNOWN
      case Some(h) =>
        val cmds = h.getLoadCommands.asScala

        // LC_BUILD_VERSION carries an explicit platform enum.
        cmds.collectFirst { case bv: BuildVersionCommand =>
          MachoPlatform.fromBuildVersionPlatform(bv.getPlatform)
        } match
          case Some(p) if p != MachoPlatform.UNKNOWN => p
          case _ =>
            // Fall back to LC_VERSION_MIN_* command types.
            cmds.collectFirst {
              case lc: VersionMinCommand =>
                lc.getCommandType match
                  case LoadCommandTypes.LC_VERSION_MIN_MACOSX   => MachoPlatform.MACOS
                  case LoadCommandTypes.LC_VERSION_MIN_IPHONEOS => MachoPlatform.IOS
                  case LoadCommandTypes.LC_VERSION_MIN_TVOS     => MachoPlatform.TVOS
                  case LoadCommandTypes.LC_VERSION_MIN_WATCHOS  => MachoPlatform.WATCHOS
                  case _                                        => MachoPlatform.UNKNOWN
            }.getOrElse(MachoPlatform.UNKNOWN)

  /** True iff the binary's CPU subtype is `CPU_SUBTYPE_ARM64E` (pointer
   *  authentication). Masked because the high byte of cpuSubType
   *  carries flags that must be ignored for subtype comparison.
   */
  def isArm64e(prog: Program): Boolean =
    header(prog).exists { h =>
      (h.getCpuSubType & CPU_SUBTYPE_MASK) == CPU_SUBTYPE_ARM64E
    }

  /** True iff any LC_ENCRYPTION_INFO[_64] load command has cryptid != 0
   *  (FairPlay-encrypted).
   */
  def isEncrypted(prog: Program): Boolean = encryptionCryptId(prog).exists(_ != 0)

  /** The cryptid from the first LC_ENCRYPTION_INFO[_64] command, or
   *  `None` if the command is absent.
   */
  def encryptionCryptId(prog: Program): Option[Int] =
    header(prog).flatMap { h =>
      h.getLoadCommands.asScala.collectFirst {
        case e: EncryptedInformationCommand => e.getCryptID
      }
    }

  /** True iff LC_DYLD_CHAINED_FIXUPS is present (iOS 15+ and recent
   *  macOS binaries use chained fixups instead of LC_DYLD_INFO_ONLY).
   */
  def usesChainedFixups(prog: Program): Boolean =
    header(prog).exists { h =>
      h.getLoadCommands.asScala.exists { lc =>
        lc.getCommandType == LoadCommandTypes.LC_DYLD_CHAINED_FIXUPS
      }
    }

  /** Raises `MachoEncryptedException` if the binary refuses to be
   *  processed because its `__TEXT` is FairPlay-encrypted.
   *  No-op for non-Mach-O binaries and for Mach-O binaries with
   *  `cryptid == 0`.
   */
  def assertNotEncrypted(prog: Program): Unit =
    encryptionCryptId(prog) match
      case Some(id) if id != 0 => throw new MachoEncryptedException(id)
      case _                   => ()
