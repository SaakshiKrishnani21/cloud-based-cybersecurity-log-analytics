public class ClassificationTest {

    public static void main(String[] args) {
        check("4 failures", 4, 0, 0, "MONITOR");
        check("5 failures", 5, 0, 0, "SUSPICIOUS");
        check("3 invalid users", 0, 3, 0, "REVIEW");
        check("1 break-in warning", 0, 0, 1, "REVIEW");
        check("successful login only", 0, 0, 0, "MONITOR");
        check("suspicious takes priority", 5, 3, 1, "SUSPICIOUS");

        System.out.println("All classification tests passed.");
    }

    static void check(String name, int failed, int invalid,
                      int warning, String expected) {
        String actual =
                SecurityClassifier.classify(failed, invalid, warning);

        if (!expected.equals(actual)) {
            throw new AssertionError(
                    name + ": expected " + expected + ", got " + actual
            );
        }

        System.out.println("PASS: " + name);
    }
}
