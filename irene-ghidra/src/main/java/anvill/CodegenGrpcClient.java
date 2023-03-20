package anvill;

import ghidra.util.Msg;
import io.grpc.Channel;
import io.grpc.StatusRuntimeException;
import irene.server.IreneGrpc;
import irene.server.Service.Codegen;
import java.util.Optional;
import specification.SpecificationOuterClass.Specification;

public class CodegenGrpcClient {

  private final IreneGrpc.IreneBlockingStub blockingStub;

  public CodegenGrpcClient(Channel channel) {
    blockingStub = IreneGrpc.newBlockingStub(channel);
  }

  public Optional<Codegen> processSpec(Specification spec) {
    Msg.info(this, "Sending specification to server");
    Codegen response;
    try {
      response = blockingStub.processSpecification(spec);
    } catch (StatusRuntimeException e) {
      Msg.warn(this, "RPC failed: " + e.getMessage());
      return Optional.empty();
    }
    return Optional.of(response);
  }
}
