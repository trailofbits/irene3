import anvill.CodegenGrpcClient;
import anvill.ProgramSpecifier;
import ghidra.app.script.GhidraScript;
import ghidra.util.Msg;
import io.grpc.*;
import java.util.concurrent.TimeUnit;
import specification.specification.Specification;

/**
 * Script that does on-demand decompilation of a single function.
 */
public class DecompileSingleFunctionRpc extends GhidraScript {

  public void run() throws Exception {
    int port = askInt("Server Port", "Please enter the IRENE gRPC server port:");
    if (port > 65535 || port < 0) {
      Msg.showError(this, null, "Invalid Port", "Please enter a port number between 0 and 65536.");
      return;
    }
    String target = "localhost:" + port;
    ManagedChannel channel = Grpc.newChannelBuilder(target, InsecureChannelCredentials.create())
        .build();
    try {
      CodegenGrpcClient client = new CodegenGrpcClient(channel);
      var func = this.currentProgram.getFunctionManager()
          .getFunctionContaining(currentLocation.getAddress());
      var spec = ProgramSpecifier.specifySingleFunction(func);
      client.processSpec(Specification.toJavaProto(spec)).ifPresent(codegen -> {
        println("Got codegen back!");
        println(codegen.getJson());
      });
    } finally {
      channel.shutdownNow().awaitTermination(5, TimeUnit.SECONDS);
    }
  }
}
