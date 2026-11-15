import java.lang.reflect.Constructor;
import java.lang.reflect.Method;

public final class HelloJvm {
  private static final String[] TEST_NAMES = {
      "001-HelloWorld",
      "002-sleep",
      "003-omnibus-opcodes",
  };

  private static final String[] TEST_PATHS = {
      "/data/local/tmp/art-official-001.dex",
      "/data/local/tmp/art-official-002.dex",
      "/data/local/tmp/art-official-003.dex",
  };

  private static void runTest(String name, String path) throws Exception {
    Class<?> loaderClass = Class.forName("dalvik.system.DexClassLoader");
    Constructor<?> constructor = loaderClass.getConstructor(
        String.class, String.class, String.class, ClassLoader.class);
    ClassLoader loader = (ClassLoader) constructor.newInstance(
        path, null, null, ClassLoader.getSystemClassLoader());
    Class<?> mainClass = Class.forName("Main", true, loader);
    Method main = mainClass.getMethod("main", String[].class);
    main.invoke(null, (Object) new String[0]);
    System.out.println("AOSP_ART_TEST_PASS name=" + name);
  }

  public static void main(String[] args) throws Exception {
    for (int i = 0; i < TEST_NAMES.length; ++i) {
      runTest(TEST_NAMES[i], TEST_PATHS[i]);
    }
    System.out.println("AOSP_ART_TEST_SUITE_PASS count=" + TEST_NAMES.length);
    long value = 0;
    for (int i = 0; i < 1000; ++i) {
      value += i;
    }
    System.out.println("JVM_OK value=" + value + " java=" +
        System.getProperty("java.version"));
  }
}
