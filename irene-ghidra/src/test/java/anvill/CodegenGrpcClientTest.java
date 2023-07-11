package anvill;

import static org.junit.Assert.assertEquals;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.test.ClassicSampleX86ProgramBuilder;
import ghidra.test.TestEnv;
import io.grpc.ManagedChannel;
import io.grpc.inprocess.InProcessChannelBuilder;
import io.grpc.inprocess.InProcessServerBuilder;
import io.grpc.stub.StreamObserver;
import io.grpc.testing.GrpcCleanupRule;
import irene.server.IreneGrpc;
import irene.server.Service;
import irene.server.Service.Codegen;
import java.io.IOException;
import java.util.Optional;
import java.util.stream.StreamSupport;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import specification.SpecificationOuterClass;
import specification.specification.Specification;

public class CodegenGrpcClientTest extends AbstractGhidraHeadlessIntegrationTest {

  private Program program;
  protected TestEnv env;
  protected String startAddressString = "0100415a"; // sscanf
  /**
   * This rule manages automatic graceful shutdown for the registered servers and channels at the
   * end of test.
   */
  @Rule public final GrpcCleanupRule grpcCleanup = new GrpcCleanupRule();

  @Before
  public void setUp() throws Exception {
    env = new TestEnv(this.getClass().getName());
    program = new ClassicSampleX86ProgramBuilder("codegen_grpc_test", true).getProgram();
  }

  @After
  public void tearDown() {
    if (program != null && env != null) {
      env.release(program);
    }
    program = null;
    if (env != null) {
      env.dispose();
    }
    env = null;
  }

  @Test
  public void processSpec() throws IOException {
    IreneGrpc.IreneImplBase serviceImpl =
        new IreneGrpc.IreneImplBase() {
          @Override
          public io.grpc.stub.StreamObserver<irene.server.Service.SpecChunk> processSpecification(
              io.grpc.stub.StreamObserver<irene.server.Service.Codegen> responseObserver) {

            return new StreamObserver<Service.SpecChunk>() {
              @Override
              public void onNext(Service.SpecChunk specChunk) {}

              @Override
              public void onError(Throwable throwable) {}

              @Override
              public void onCompleted() {
                responseObserver.onNext(Codegen.getDefaultInstance());
                responseObserver.onCompleted();
              }
            };
          }
        };

    // Generate a unique in-process server name.
    String serverName = InProcessServerBuilder.generateName();

    // Create a server, add service, start, and register for automatic graceful shutdown.
    grpcCleanup.register(
        InProcessServerBuilder.forName(serverName)
            .directExecutor()
            .addService(serviceImpl)
            .build()
            .start());

    // Create a client channel and register for automatic graceful shutdown.
    ManagedChannel channel =
        grpcCleanup.register(InProcessChannelBuilder.forName(serverName).directExecutor().build());

    // Create a CodegenGrpcClient using the in-process channel;
    var client = new CodegenGrpcClient(channel);

    Function sscanf =
        StreamSupport.stream(program.getFunctionManager().getFunctions(true).spliterator(), false)
            .filter(function -> "sscanf".equals(function.getName()))
            .findFirst()
            .get();

    Specification spec;
    var id = program.startTransaction("Generating anvill patch");
    try {
      spec =
          ProgramSpecifier.specifySingleFunction(
              sscanf, new scala.collection.immutable.HashSet<>());
    } finally {
      program.endTransaction(id, false);
    }
    SpecificationOuterClass.Specification exp = Specification.toJavaProto(spec);

    Optional<Codegen> resp = client.processSpec(exp);

    assertEquals(resp.get(), Codegen.getDefaultInstance());
  }
}
