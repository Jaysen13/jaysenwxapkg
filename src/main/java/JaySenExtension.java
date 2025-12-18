import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

public class JaySenExtension implements BurpExtension {
    @Override
    public void initialize(MontoyaApi montoyaApi) {
        montoyaApi.extension().setName("JaySenWxapkg");
        montoyaApi.logging().logToOutput("""
                 ___       __      ___    ___ ________  ________  ___  __    ________  ___      ___  _____      ________    \s
                |\\  \\     |\\  \\   |\\  \\  /  /|\\   __  \\|\\   __  \\|\\  \\|\\  \\ |\\   ____\\|\\  \\    /  /|/ __  \\    |\\   __  \\   \s
                \\ \\  \\    \\ \\  \\  \\ \\  \\/  / | \\  \\|\\  \\ \\  \\|\\  \\ \\  \\/  /|\\ \\  \\___|\\ \\  \\  /  / /\\/_|\\  \\   \\ \\  \\|\\  \\  \s
                 \\ \\  \\  __\\ \\  \\  \\ \\    / / \\ \\   __  \\ \\   ____\\ \\   ___  \\ \\  \\  __\\ \\  \\/  / /\\|/ \\ \\  \\   \\ \\  \\\\\\  \\ \s
                  \\ \\  \\|\\__\\_\\  \\  /     \\/   \\ \\  \\ \\  \\ \\  \\___|\\ \\  \\\\ \\  \\ \\  \\|\\  \\ \\    / /      \\ \\  \\ __\\ \\  \\\\\\  \\\s
                   \\ \\____________\\/  /\\   \\    \\ \\__\\ \\__\\ \\__\\    \\ \\__\\\\ \\__\\ \\_______\\ \\__/ /        \\ \\__\\\\__\\ \\_______\\
                    \\|____________/__/ /\\ __\\    \\|__|\\|__|\\|__|     \\|__| \\|__|\\|_______|\\|__|/          \\|__\\|__|\\|_______|
                                  |__|/ \\|__|                                                                               \s
                
                Author: jaysen
                Github: https://github.com/Jaysen13/jaysenscan
                Gitee: https://gitee.com/qiudaoyu_liao/jaysenscan
                Version: V1.1
                """);
        // 注册标签页面
        JaySenSuiteTab jaysenSuiteTab = new JaySenSuiteTab();
        montoyaApi.userInterface().registerSuiteTab("JaySenWxapkg", jaysenSuiteTab.getUiComponent());
    }
}