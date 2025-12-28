/*
 * JaySenWxapkg - Burp Suite 微信小程序解包插件
 *
 * Copyright (C) 2025 JaySen (Jaysen13)
 *
 * 本软件采用 CC BY-NC-SA 4.0 许可证进行许可
 * 禁止用于商业售卖，允许非商业使用、修改和分享，衍生品需采用相同许可证
 *
 * 作者：JaySen
 * 邮箱：3147330392@qq.com
 * GitHub：https://github.com/Jaysen13/jaysenwxapkg
 * 许可证详情：参见项目根目录 LICENSE 文件
 */
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
                Github: https://github.com/Jaysen13/jaysenwxapkg
                Gitee: https://gitee.com/qiudaoyu_liao/jaysenwxapkg
                Version: V1.0
                """);
        // 注册标签页面
        JaySenSuiteTab jaysenSuiteTab = new JaySenSuiteTab();
        montoyaApi.userInterface().registerSuiteTab("JaySenWxapkg", jaysenSuiteTab.getUiComponent());
    }
}