package anvill.decompiler;

public class DecompilerServerException extends Exception {

  public DecompilerServerException() {}

  public DecompilerServerException(String message) {
    super(message);
  }

  public DecompilerServerException(String message, Throwable cause) {
    super(message, cause);
  }

  public DecompilerServerException(Throwable cause) {
    super(cause);
  }

  public DecompilerServerException(
      String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
    super(message, cause, enableSuppression, writableStackTrace);
  }
}
