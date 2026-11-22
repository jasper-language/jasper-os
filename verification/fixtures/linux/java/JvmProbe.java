import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicLong;

public final class JvmProbe {
    public static void main(String[] args) throws Exception {
        long value = 0;
        for (int i = 0; i < 1000; i++) value += i;

        AtomicLong threadValue = new AtomicLong();
        CountDownLatch ready = new CountDownLatch(1);
        Thread worker = new Thread(() -> {
            long sum = 0;
            for (int i = 0; i < 1000; i++) sum += i;
            threadValue.set(sum);
            ready.countDown();
        }, "jvm-probe-worker");
        worker.start();
        ready.await();
        worker.join();

        byte[] garbage = new byte[1024 * 1024];
        Arrays.fill(garbage, (byte)0x5a);
        long gcValue = garbage[0] + garbage[garbage.length - 1];

        Path file = Path.of("/data/runtimes/openjdk/probe.tmp");
        byte[] payload = "JASPER_JVM_FILE_OK".getBytes(StandardCharsets.US_ASCII);
        try (OutputStream output = Files.newOutputStream(file)) {
            output.write(payload);
        }
        boolean fileOk = Files.size(file) == payload.length;

        boolean ok = value == 499500
            && threadValue.get() == 499500
            && gcValue == 0xb4
            && fileOk;
        if (!ok) {
            throw new IllegalStateException("JVM probe invariant failed");
        }
        System.out.printf(
            "JVM_PROBE_OK value=%d thread=%s gc=%s file=%s java=%s%n",
            value, threadValue.get() == 499500, gcValue == 0xb4,
            fileOk, System.getProperty("java.version"));
    }
}
