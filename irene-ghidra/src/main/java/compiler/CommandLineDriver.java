package compiler;

import java.io.File;
import java.nio.file.Path;
import java.util.Optional;

public interface CommandLineDriver {
  void dispose();

  void runCommand(
      String[] cmd,
      Optional<File> stdin_redirect,
      Optional<File> stdout_redirect,
      Optional<File> stderr_redirect)
      throws CommandLineDriverException;

  void setWdir(Path wdir);
}
