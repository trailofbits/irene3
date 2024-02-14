package anvill;

import ghidra.util.Msg;
import io.grpc.Channel;
import io.grpc.StatusRuntimeException;
import io.grpc.stub.StreamObserver;
import irene3.server.PatchLangServerGrpc;
import irene3.server.PatchService;
import irene3.server.PatchService.PatchGraph;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import specification.SpecificationOuterClass.Specification;

public class PatchLangGrpcClient {

  private final PatchLangServerGrpc.PatchLangServerStub asyncStub;
  private final PatchLangServerGrpc.PatchLangServerBlockingStub blockingStub;

  public static final int CHUNK_SIZE = 2000000;

  public PatchLangGrpcClient(Channel channel) {
    asyncStub = PatchLangServerGrpc.newStub(channel);
    blockingStub = PatchLangServerGrpc.newBlockingStub(channel);
  }

  public Optional<PatchGraph> processSpec(Specification spec) throws StatusRuntimeException {
    Msg.info(this, "Attempting to send specification to server...");

    var sobs =
        new StreamObserver<PatchGraph>() {
          Optional<PatchGraph> response = Optional.empty();
          Optional<Throwable> error = Optional.empty();
          final CountDownLatch finishLatch = new CountDownLatch(1);

          @Override
          public void onNext(PatchGraph patchGraph) {
            response = Optional.of(patchGraph);
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
    var resp_obs = asyncStub.generatePatchGraph(sobs);

    var encoded = spec.toByteString();
    int ind = 0;

    while (ind < encoded.size()) {
      var next_end = Integer.min(encoded.size(), ind + CHUNK_SIZE);
      var chunk =
          PatchService.SpecChunk.newBuilder().setChunk(encoded.substring(ind, next_end)).build();
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

  public Optional<PatchService.PatchResponse> applyPatch(PatchService.PatchRequest request)
      throws StatusRuntimeException {
    Msg.info(this, "Attempting to send PatchRequest to server...");
    Optional<PatchService.PatchResponse> ret;
    try {
      ret = Optional.of(blockingStub.applyPatch(request));
    } catch (StatusRuntimeException e) {
      Msg.warn(this, "RPC failed: " + e.getStatus());
      ret = Optional.empty();
    }
    Msg.info(this, "Got PatchResponse from server!");
    return ret;
  }
}
