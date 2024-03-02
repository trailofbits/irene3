package compiler;

public class CommandLineDriverException extends Exception {
  public CommandLineDriverException() {}

  public CommandLineDriverException(String message) {
    super(message);
  }

  public CommandLineDriverException(String message, Throwable cause) {
    super(message, cause);
  }

  public CommandLineDriverException(Throwable cause) {
    super(cause);
  }
}
