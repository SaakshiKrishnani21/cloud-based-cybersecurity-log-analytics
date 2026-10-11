import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class SecurityLogParser {

    private static final Pattern SOURCE_PATTERN =
            Pattern.compile(
                "(?:\\bfrom\\s+|\\brhost=|\\bby\\s+)(\\[[^\\]]+\\]|[^\\s,]+)"
            );

    private static final Pattern BRACKETED_IP_PATTERN =
            Pattern.compile("\\[([^\\]]+)\\]");

    private SecurityLogParser() {}

    public static boolean isValidIPv4(String ip) {
        if (ip == null) {
            return false;
        }

        String[] octets = ip.split("\\.", -1);

        if (octets.length != 4) {
            return false;
        }

        for (String octet : octets) {
            if (octet.isEmpty() || octet.length() > 3) {
                return false;
            }

            for (int i = 0; i < octet.length(); i++) {
                if (!Character.isDigit(octet.charAt(i))) {
                    return false;
                }
            }

            try {
                if (Integer.parseInt(octet) > 255) {
                    return false;
                }
            } catch (NumberFormatException e) {
                return false;
            }
        }

        return true;
    }

    public static String[] parse(String line) {
        if (line == null || line.isEmpty()) {
            return null;
        }

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
            ip = normalizeIp(sourceMatcher.group(1));

            // Do not fall back to a different IP if the source is invalid.
            if (!isValidIPv4(ip)) {
                return null;
            }
        } else {
            // Some OpenSSH warnings contain the address in square brackets.
            Matcher bracketMatcher =
                    BRACKETED_IP_PATTERN.matcher(line);

            while (bracketMatcher.find()) {
                String candidate = bracketMatcher.group(1);

                if (isValidIPv4(candidate)) {
                    ip = candidate;
                    break;
                }
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

    private static String normalizeIp(String candidate) {
        if (candidate.startsWith("[") && candidate.endsWith("]")) {
            return candidate.substring(1, candidate.length() - 1);
        }

        return candidate;
    }
}
