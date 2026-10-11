public class ParserTest {

    public static void main(String[] args) {
        check("Failed password",
            "Dec 10 sshd: Failed password for alice from 173.234.31.186",
            "173.234.31.186", "1,0,0,0");

        check("Invalid user",
            "Dec 10 sshd: Invalid user test9 from 52.80.34.196",
            "52.80.34.196", "0,1,0,0");

        check("Successful public key login",
            "Dec 10 sshd: Accepted publickey for ubuntu from 192.168.1.10",
            "192.168.1.10", "0,0,1,0");

        check("Break-in warning without IP",
            "sshd: reverse mapping failed - POSSIBLE BREAK-IN ATTEMPT!",
            null, null);

        check("Unrelated log line",
            "systemd: Started a service",
            null, null);

        check("Security event without IP",
            "sshd: Failed password for alice",
            null, null);

        check("Bracketed IPv4 warning",
            "sshd: POSSIBLE BREAK-IN ATTEMPT [173.234.31.186]",
            "173.234.31.186", "0,0,0,1");

        check("Invalid IPv4 rejected",
            "sshd: Failed password for alice from 999.300.1.2",
            null, null);

        check("Invalid source does not use unrelated IP",
            "sshd: POSSIBLE BREAK-IN ATTEMPT [173.234.31.186] from 999.300.1.2",
            null, null);

        check("Unrelated bracketed IP ignored",
            "systemd: Started service [192.168.1.10]",
            null, null);

        check("Null input", null, null, null);
        check("Empty input", "", null, null);

        checkIp("Minimum IPv4", "0.0.0.0", true);
        checkIp("Maximum IPv4", "255.255.255.255", true);
        checkIp("Octet above 255", "192.168.1.256", false);
        checkIp("First octet above 255", "999.1.2.3", false);
        checkIp("Missing octet", "192.168.1", false);
        checkIp("Extra octet", "192.168.1.10.5", false);
        checkIp("Empty octet", "192.168..10", false);
        checkIp("Non-numeric octet", "192.168.x.10", false);
        checkIp("Null IP", null, false);

        System.out.println("All parser tests passed.");
    }

    static void check(String name, String line,
                      String expectedIp, String expectedCounts) {
        String[] result = SecurityLogParser.parse(line);

        if (expectedIp == null) {
            if (result != null) {
                throw new AssertionError(name + ": expected line to be ignored");
            }
        } else {
            if (result == null
                    || !expectedIp.equals(result[0])
                    || !expectedCounts.equals(result[1])) {
                throw new AssertionError(name + ": unexpected parse result");
            }
        }

        System.out.println("PASS: " + name);
    }

    static void checkIp(String name, String ip, boolean expected) {
        boolean actual = SecurityLogParser.isValidIPv4(ip);

        if (actual != expected) {
            throw new AssertionError(name + ": expected "
                + expected + ", got " + actual);
        }

        System.out.println("PASS: " + name);
    }
}
