package anvill.macho

/** The Apple platform a Mach-O binary targets, as encoded by
 *  LC_VERSION_MIN_* / LC_BUILD_VERSION load commands.
 */
enum MachoPlatform:
  case MACOS
  case IOS
  case TVOS
  case WATCHOS
  case BRIDGE_OS
  case MAC_CATALYST
  case IOS_SIMULATOR
  case TVOS_SIMULATOR
  case WATCHOS_SIMULATOR
  case DRIVER_KIT
  case VISION_OS
  case UNKNOWN

object MachoPlatform:

  /** LC_BUILD_VERSION.platform encoding.
   *  See Apple's `mach-o/loader.h`.
   */
  def fromBuildVersionPlatform(platform: Int): MachoPlatform = platform match
    case 1  => MACOS
    case 2  => IOS
    case 3  => TVOS
    case 4  => WATCHOS
    case 5  => BRIDGE_OS
    case 6  => MAC_CATALYST
    case 7  => IOS_SIMULATOR
    case 8  => TVOS_SIMULATOR
    case 9  => WATCHOS_SIMULATOR
    case 10 => DRIVER_KIT
    case 11 => VISION_OS
    case _  => UNKNOWN
