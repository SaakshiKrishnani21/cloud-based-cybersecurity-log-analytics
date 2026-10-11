public class ParserTest {

    public static void main(String[] args) {
        check(
            "Failed password",
            "Dec 10 06:55:48 LabSZ sshd[24200]: Failed password for invalid user webmaster from 173.234.31.186 port 38926 ssh2",
            "173.234.31.186", "1,0,0,0"
        );

        check(
            "Invalid user",
            "Dec 10 07:07:38 LabSZ sshd[24206]: Invalid user test9 from 52.80.34.196",
            "52.80.34.196", "0,1,0,0"
        );

        check(
            "Successful public key login",
            "Dec 10 08:00:00 LabSZ sshd[24210]: Accepted publickey for ubuntu from 192.168.1.10 port 22 ssh2",
            "192.168.1.10", "0,0,1,0"
        );

        check(
            "Break-in warning",
            "Dec 10 06:55:46 LabSZ sshd[24200]: reverse mapping failed - POSSIBLE BREAK-IN ATTEMPT!",
            null, null
        );

        check(
            "Unrelated log line",
            "Dec 10 09:00:00 LabSZ systemd: Started a service",
            null, null
        );

        check(
            "Security event without IP",
            "sshd: Failed password for user alice",
            null, null
        );

        System.out.println("All parser tests passed.");
    }

    static void check(String name, String line,
                      String expectedIp, String expectedCounts) {
        String[] result = SecurityLogParser.parse(line);

        if (expectedIp == null) {
            if (result != null) {
                throw new AssertionError(
                    name + ": expected the line to be ignored"
                );
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
}
