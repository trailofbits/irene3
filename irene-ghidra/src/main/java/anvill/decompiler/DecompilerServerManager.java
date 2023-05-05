package anvill.decompiler;

public interface DecompilerServerManager {

  /**
   * Start the server. Calling this multiple times should not result in an error if the server is
   * already started.
   *
   * <p>An exception is only thrown if we cannot start the server for some reason.
   */
  default void startDecompilerServer() throws DecompilerServerException {}

  /** Clean up server */
  void dispose();
}
