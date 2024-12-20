package artsploit;

public class RogueJndi {

    public static void main(String[] args) throws Exception {
        var splashScreen =  """
                __________ ________    ________ ____ ______________      ____._______  ________  .___   _______    ________\s
                \\______   \\\\_____  \\  /  _____/|    |   \\_   _____/     |    |\\      \\ \\______ \\ |   |  \\      \\  /  _____/\s
                 |       _/ /   |   \\/   \\  ___|    |   /|    __)_      |    |/   |   \\ |    |  \\|   |  /   |   \\/   \\  ___\s
                 |    |   \\/    |    \\    \\_\\  \\    |  / |        \\ /\\__|    /    |    \\|    `   \\   | /    |    \\    \\_\\  \\
                 |____|_  /\\_______  /\\______  /______/ /_______  / \\________\\____|__  /_______  /___| \\____|__  /\\______  /
                        \\/         \\/        \\/                 \\/                   \\/        \\/              \\/        \\/
        
        """;
        System.out.println(splashScreen);

        Config.applyCmdArgs(args);
        HttpServer.start();
        LdapServer.start();
    }
}