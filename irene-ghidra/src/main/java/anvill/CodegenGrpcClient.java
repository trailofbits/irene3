package anvill;

import ghidra.util.Msg;
import io.grpc.Channel;
import io.grpc.StatusRuntimeException;
import io.grpc.stub.StreamObserver;
import irene.server.IreneGrpc;
import irene.server.Service;
import irene.server.Service.Codegen;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import specification.SpecificationOuterClass.Specification;

public class CodegenGrpcClient {

  private final IreneGrpc.IreneStub asyncStub;

  public static final int CHUNK_SIZE = 2000000;

  public CodegenGrpcClient(Channel channel) {
    asyncStub = IreneGrpc.newStub(channel);
  }

  public Optional<Codegen> processSpec(Specification spec) throws StatusRuntimeException {
    Msg.info(this, "Attempting to send specification to server...");

    var sobs =
        new StreamObserver<Codegen>() {
          Optional<Codegen> response = Optional.empty();
          Optional<Throwable> error = Optional.empty();
          final CountDownLatch finishLatch = new CountDownLatch(1);

          @Override
          public void onNext(Codegen codegen) {
            response = Optional.of(codegen);
          }

          @Override
          public void onError(Throwable throwable) {
            error = Optional.of(throwable);
            finishLatch.countDown();
          }

          @Override
          public void onCompleted() {
            finishLatch.countDown();
          }
        };
    var resp_obs = asyncStub.processSpecification(sobs);

    var encoded = spec.toByteString();
    int ind = 0;

    while (ind < encoded.size()) {
      var next_end = Integer.min(encoded.size(), ind + CHUNK_SIZE);
      var chunk = Service.SpecChunk.newBuilder().setChunk(encoded.substring(ind, next_end)).build();
      resp_obs.onNext(chunk);
      ind += CHUNK_SIZE;
    }

    resp_obs.onCompleted();

    try {
      sobs.finishLatch.await(5, TimeUnit.MINUTES);
    } catch (InterruptedException e) {
      Msg.warn(this, "GRPC call timed out");
    }
    if (sobs.error.isPresent()) {
      Throwable e = sobs.error.get();
      if (e instanceof StatusRuntimeException) throw (StatusRuntimeException) e;
      else throw (RuntimeException) e;
    }

    Msg.info(this, "Sent specification to server!");
    return sobs.response;
  }
}
