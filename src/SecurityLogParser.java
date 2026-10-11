import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class SecurityLogParser {

    private static final Pattern IP_PATTERN =
            Pattern.compile("\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b");

    private static final Pattern SOURCE_PATTERN =
            Pattern.compile(
                "(?:from|rhost=|by)\\s+((?:\\d{1,3}\\.){3}\\d{1,3})"
            );

    private SecurityLogParser() {}

    public static String[] parse(String line) {
        int failed = line.contains("Failed password") ? 1 : 0;
        int invalid = line.contains("Invalid user") ? 1 : 0;
        int success =
                (line.contains("Accepted password")
                || line.contains("Accepted publickey")) ? 1 : 0;
        int warning =
                line.contains("POSSIBLE BREAK-IN ATTEMPT") ? 1 : 0;

        if (failed + invalid + success + warning == 0) {
            return null;
        }

        String ip = null;
        Matcher sourceMatcher = SOURCE_PATTERN.matcher(line);

        if (sourceMatcher.find()) {
            ip = sourceMatcher.group(1);
        } else {
            Matcher ipMatcher = IP_PATTERN.matcher(line);
            if (ipMatcher.find()) {
                ip = ipMatcher.group();
            }
        }

        if (ip == null) {
            return null;
        }

        return new String[] {
            ip,
            failed + "," + invalid + "," + success + "," + warning
        };
    }
}
