package anvill.decompiler;

import com.github.dockerjava.api.command.CreateContainerResponse;
import com.github.dockerjava.api.exception.DockerException;
import com.github.dockerjava.api.model.ExposedPort;
import com.github.dockerjava.api.model.HostConfig;
import com.github.dockerjava.api.model.PortBinding;

public class DockerDecompilerServerManager extends DockerClientManager
    implements DecompilerServerManager {
  public static final String IMAGE_NAME = "irene3:latest";
  public static final String CONTAINER_NAME = "irene-decompiler-server";
  public static final String EXECUTABLE = "irene3-server";
  public static final String EXPOSED_PORT = "50080";
  private final int port;
  private CreateContainerResponse decompilerContainer;

  /**
   * Start a decompiler server through Docker.
   *
   * @param port Port number to use for communication
   */
  public DockerDecompilerServerManager(int port) {
    this.port = port;
  }

  public void startDecompilerServer() throws DecompilerServerException {
    startDecompilerServer(EXECUTABLE, "--unsafe-stack-locations=1");
  }

  public void startPatchLangServer() throws DecompilerServerException {
    startDecompilerServer("irene3-patchlang-server", "--logtostderr");
  }

  /** Start the decompiler server. */
  public void startDecompilerServer(String executable, String cmd)
      throws DecompilerServerException {
    setupDockerClient();

    // Check if it's already running/created
    if (decompilerContainer != null) {
      var inspect = dockerClient.inspectContainerCmd(decompilerContainer.getId()).exec();
      var state = inspect.getState();
      if (state != null) {
        if (Boolean.TRUE.equals(state.getRunning())) return;
      }
    } else {
      // Start the server
      try {
        dockerClient.stopContainerCmd(CONTAINER_NAME).exec();
      } catch (DockerException ignored) {

      }
      try {
        dockerClient.removeContainerCmd(CONTAINER_NAME).exec();
      } catch (DockerException ignored) {

      }

      try {

        decompilerContainer =
            dockerClient
                .createContainerCmd(IMAGE_NAME)
                .withEntrypoint(executable)
                .withCmd(cmd)
                .withName(CONTAINER_NAME)
                .withHostConfig(
                    new HostConfig().withPortBindings(PortBinding.parse(port + ":" + EXPOSED_PORT)))
                .withExposedPorts(ExposedPort.parse(EXPOSED_PORT))
                .exec();
      } catch (DockerException e) {
        throw new DecompilerServerException(
            "Something went wrong trying to create the decompiler container", e);
      }
    }
    try {
      dockerClient.startContainerCmd(decompilerContainer.getId()).exec();
    } catch (DockerException e) {
      throw new DecompilerServerException(
          "Something went wrong trying to start the decompiler container", e);
    }
  }

  /** Set up a connection to Docker. */
  public void dispose() {
    if (decompilerContainer != null) {
      var containerId = decompilerContainer.getId();
      var state = dockerClient.inspectContainerCmd(containerId).exec().getState();
      if (state != null) {
        if (Boolean.TRUE.equals(state.getRunning())) {
          dockerClient.killContainerCmd(containerId).exec();
        }
      }
      dockerClient.removeContainerCmd(containerId).exec();
      decompilerContainer = null;
    }
  }
}
