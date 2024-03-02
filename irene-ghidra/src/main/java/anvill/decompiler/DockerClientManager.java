package anvill.decompiler;

import com.github.dockerjava.api.DockerClient;
import com.github.dockerjava.core.DefaultDockerClientConfig;
import com.github.dockerjava.core.DockerClientBuilder;
import com.github.dockerjava.zerodep.ZerodepDockerHttpClient;
import javax.ws.rs.ProcessingException;

public class DockerClientManager {
  protected DockerClient dockerClient;

  protected void setupDockerClient() throws DecompilerServerException {
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

  protected void testDockerIsConnected() throws DecompilerServerException {
    try {
      dockerClient.pingCmd().exec();
    } catch (ProcessingException exception) {
      throw new DecompilerServerException(
          "Please install or start Docker on this computer", exception);
    }
  }
}
