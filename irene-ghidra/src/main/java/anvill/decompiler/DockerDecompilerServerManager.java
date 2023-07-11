package anvill.decompiler;

import com.github.dockerjava.api.DockerClient;
import com.github.dockerjava.api.command.CreateContainerResponse;
import com.github.dockerjava.api.exception.DockerException;
import com.github.dockerjava.api.model.ExposedPort;
import com.github.dockerjava.api.model.HostConfig;
import com.github.dockerjava.api.model.PortBinding;
import com.github.dockerjava.core.DefaultDockerClientConfig;
import com.github.dockerjava.core.DockerClientBuilder;
import com.github.dockerjava.zerodep.ZerodepDockerHttpClient;
import javax.ws.rs.ProcessingException;

public class DockerDecompilerServerManager implements DecompilerServerManager {
  public static final String IMAGE_NAME = "irene3:latest";
  public static final String CONTAINER_NAME = "irene-decompiler-server";
  public static final String EXECUTABLE = "irene3-server";
  public static final String EXPOSED_PORT = "50080";
  private final int port;
  private DockerClient dockerClient;
  private CreateContainerResponse decompilerContainer;

  /**
   * Start a decompiler server through Docker.
   *
   * @param port Port number to use for communication
   */
  public DockerDecompilerServerManager(int port) {
    this.port = port;
  }

  /** Start the decompiler server. */
  public void startDecompilerServer() throws DecompilerServerException {
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
        decompilerContainer =
            dockerClient
                .createContainerCmd(IMAGE_NAME)
                .withEntrypoint(EXECUTABLE)
                .withCmd("--unsafe-stack-locations=1")
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
  private void setupDockerClient() throws DecompilerServerException {
    if (dockerClient == null) {
      dockerClient =
          DockerClientBuilder.getInstance()
              .withDockerHttpClient(
                  new ZerodepDockerHttpClient.Builder()
                      .dockerHost(
                          DefaultDockerClientConfig.createDefaultConfigBuilder()
                              .build()
                              .getDockerHost())
                      .build())
              .build();
      if (dockerClient == null) {
        throw new DecompilerServerException(
            "Could not find Docker. Please install or start Docker on this computer");
      }
    }

    // Check that Docker is actually available
    testDockerIsConnected();
  }

  private void testDockerIsConnected() throws DecompilerServerException {
    try {
      dockerClient.pingCmd().exec();
    } catch (ProcessingException exception) {
      throw new DecompilerServerException(
          "Please install or start Docker on this computer", exception);
    }
  }

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
