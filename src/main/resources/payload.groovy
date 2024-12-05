def command = "touch /usr/local/tomcat/temp/groovy1.pwn"
def process = command.execute()
println process.text
command = "touch /usr/local/tomcat/temp/groovy2.pwn"
def process2 = command.execute()
command = "touch /usr/local/tomcat/temp/groovy3.pwn"
def process3 = command.execute()