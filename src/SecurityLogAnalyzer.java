
import java.io.IOException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.io.LongWritable;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.mapreduce.Job;
import org.apache.hadoop.mapreduce.Mapper;
import org.apache.hadoop.mapreduce.Reducer;
import org.apache.hadoop.mapreduce.lib.input.FileInputFormat;
import org.apache.hadoop.mapreduce.lib.output.FileOutputFormat;
import org.apache.hadoop.util.Tool;
import org.apache.hadoop.util.ToolRunner;
import org.apache.hadoop.conf.Configured;

public class SecurityLogAnalyzer extends Configured implements Tool {

    public static class SecurityMapper
            extends Mapper<LongWritable, Text, Text, Text> {

        private static final Pattern IP_PATTERN =
                Pattern.compile("\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b");

        private static final Pattern SOURCE_PATTERN =
                Pattern.compile(
                    "(?:from|rhost=|by)\\s+((?:\\d{1,3}\\.){3}\\d{1,3})"
                );

        private final Text ipKey = new Text();
        private final Text counts = new Text();

        public void map(LongWritable key, Text value, Context context)
                throws IOException, InterruptedException {

            String[] parsed = SecurityLogParser.parse(value.toString());

            if (parsed == null) {
                return;
            }

            ipKey.set(parsed[0]);
            counts.set(parsed[1]);

            context.write(ipKey, counts);
        }
    }

    public static class SecurityReducer
            extends Reducer<Text, Text, Text, Text> {

        public void reduce(Text ip, Iterable<Text> values,
                           Context context)
                throws IOException, InterruptedException {

            int failed = 0;
            int invalid = 0;
            int success = 0;
            int warning = 0;

            for (Text value : values) {
                String[] parts = value.toString().split(",");

                failed += Integer.parseInt(parts[0]);
                invalid += Integer.parseInt(parts[1]);
                success += Integer.parseInt(parts[2]);
                warning += Integer.parseInt(parts[3]);
            }

            String status = SecurityClassifier.classify(failed, invalid, warning);

            String report =
                    "failed_passwords=" + failed
                    + "\tinvalid_users=" + invalid
                    + "\tsuccessful_logins=" + success
                    + "\tbreak_in_warnings=" + warning
                    + "\tstatus=" + status;

            context.write(ip, new Text(report));
        }
    }

    @Override
    public int run(String[] args) throws Exception {

        if (args.length != 2) {
            System.err.println(
                "Usage: SecurityLogAnalyzer <input> <output>"
            );
            return 2;
        }

        Job job = Job.getInstance(
                getConf(), "Cybersecurity Log Analytics"
        );

        job.setJarByClass(SecurityLogAnalyzer.class);

        job.setMapperClass(SecurityMapper.class);
        job.setReducerClass(SecurityReducer.class);

        job.setMapOutputKeyClass(Text.class);
        job.setMapOutputValueClass(Text.class);

        job.setOutputKeyClass(Text.class);
        job.setOutputValueClass(Text.class);

        FileInputFormat.addInputPath(job, new Path(args[0]));
        FileOutputFormat.setOutputPath(job, new Path(args[1]));

        return job.waitForCompletion(true) ? 0 : 1;
    }

    public static void main(String[] args) throws Exception {
        int result = ToolRunner.run(
                new Configuration(),
                new SecurityLogAnalyzer(),
                args
        );

        System.exit(result);
    }
}
