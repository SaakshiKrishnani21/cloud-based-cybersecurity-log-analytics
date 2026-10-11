public final class SecurityClassifier {

    private SecurityClassifier() {
        // Prevent object creation.
    }

    public static String classify(int failed, int invalid, int warning) {
        if (failed >= 5) {
            return "SUSPICIOUS";
        } else if (warning > 0 || invalid >= 3) {
            return "REVIEW";
        } else {
            return "MONITOR";
        }
    }
}
