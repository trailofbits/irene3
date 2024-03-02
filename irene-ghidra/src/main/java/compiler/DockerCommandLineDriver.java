package compiler;

import anvill.decompiler.DecompilerServerException;
import anvill.decompiler.DockerClientManager;
import com.github.dockerjava.api.exception.DockerException;
import com.github.dockerjava.api.model.*;
import ghidra.util.Msg;
import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.stream.Collectors;

public class DockerCommandLineDriver extends DockerClientManager implements CommandLineDriver {
  public static final String IMAGE_NAME = "irene3:latest";
  private Path wdir;

  public DockerCommandLineDriver() {
    try {
      this.setupDockerClient();
    } catch (DecompilerServerException e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  public void dispose() {}

  @Override
  public void runCommand(
      String[] cmd,
      Optional<File> stdin_redirect,
      Optional<File> stdout_redirect,
      Optional<File> stderr_redirect)
      throws CommandLineDriverException {
    try {
      var volumes = Arrays.asList(new Bind(this.wdir.toString(), new Volume(this.wdir.toString())));

      var new_cmds = new ArrayList<String>();
      new_cmds.add("/bin/bash");
      new_cmds.add("-c");
      StringBuilder internal_command = new StringBuilder();
      internal_command.append(
          String.join(
              " ",
              Arrays.stream(cmd)
                  .map(
                      s -> {
                        // Shell empty string
                        if (s.isEmpty()) {
                          return "\"\"";
                        }
                        return s;
                      })
                  .collect(Collectors.toCollection(ArrayList::new))));
      stdin_redirect.ifPresent(file -> internal_command.append(" < ").append(file.toPath()));
      stdout_redirect.ifPresent(file -> internal_command.append(" > ").append(file.toPath()));
      stderr_redirect.ifPresent(file -> internal_command.append(" 2> ").append(file.toPath()));
      new_cmds.add(internal_command.toString());

      var cont =
          dockerClient.createContainerCmd(IMAGE_NAME).withCmd(new_cmds).withBinds(volumes).exec();
      dockerClient.startContainerCmd(cont.getId()).withContainerId(cont.getId()).exec();
      Msg.info(this, cont.getId());
      var latch = new CountDownLatch(1);
      final Throwable[] f = {null};
      Optional<Integer> init = Optional.empty();
      final Optional<Integer>[] status_code = (Optional<Integer>[]) new Optional[] {init};
      dockerClient
          .waitContainerCmd(cont.getId())
          .exec(
              new com.github.dockerjava.api.async.ResultCallback<
                  com.github.dockerjava.api.model.WaitResponse>() {

                @Override
                public void close() throws IOException {}

                @Override
                public void onStart(Closeable closeable) {}

                @Override
                public void onNext(WaitResponse waitResponse) {
                  status_code[0] = Optional.of(waitResponse.getStatusCode());
                }

                @Override
                public void onError(Throwable throwable) {
                  f[0] = throwable;
                  latch.countDown();
                }

                @Override
                public void onComplete() {
                  latch.countDown();
                }
              });
      latch.await();

      if (f[0] != null) {
        throw new CommandLineDriverException(f[0]);
      }

      if (status_code[0].isPresent() && status_code[0].get() != 0) {
        throw new CommandLineDriverException("Failed to run container: " + cont.getId());
      }
    } catch (DockerException | InterruptedException e) {
      throw new CommandLineDriverException(e);
    }
  }

  @Override
  public void setWdir(Path wdir) {
    this.wdir = wdir;
  }
}
