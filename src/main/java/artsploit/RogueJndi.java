package artsploit;

public class RogueJndi {

    public static void main(String[] args) throws Exception {
        String splashScreen =
               " __________ ________    ________ ____ ______________      ____._______  ________  .___   _______    ________ \n" +
               " \\______   \\\\_____  \\  /  _____/|    |   \\_   _____/     |    |\\      \\ \\______ \\ |   |  \\      \\  /  _____/ \n" +
               "  |       _/ /   |   \\/   \\  ___|    |   /|    __)_      |    |/   |   \\ |    |  \\|   |  /   |   \\/   \\  ___ \n" +
               "  |    |   \\/    |    \\    \\_\\  \\    |  / |        \\ /\\__|    /    |    \\|    `   \\   | /    |    \\    \\_\\  \\\n" +
               "  |____|_  /\\_______  /\\______  /______/ /_______  / \\________\\____|__  /_______  /___| \\____|__  /\\______  /\n" +
               "         \\/         \\/        \\/                 \\/                   \\/        \\/              \\/        \\/\n";

        System.out.println(splashScreen);

        Config.applyCmdArgs(args);
        HttpServer.start();
        LdapServer.start();
    }
}