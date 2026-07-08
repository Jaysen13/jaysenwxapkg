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
                      _              _____        __          __               _        \s
                     | |            / ____|       \\ \\        / /              | |       \s
                     | | __ _ _   _| (___   ___ _ _\\ \\  /\\  / /_  ____ _ _ __ | | ____ _\s
                 _   | |/ _` | | | |\\___ \\ / _ \\ '_ \\ \\/  \\/ /\\ \\/ / _` | '_ \\| |/ / _` |
                | |__| | (_| | |_| |____) |  __/ | | \\  /\\  /  >  < (_| | |_) |   < (_| |
                 \\____/ \\__,_|\\__, |_____/ \\___|_| |_|\\/  \\/  /_/\\_\\__,_| .__/|_|\\_\\__, |
                               __/ |                                    | |         __/ |
                              |___/                                     |_|        |___/\s
                                                                                         \s
                Author: jaysen
                Github: https://github.com/Jaysen13/jaysenwxapkg
                Version: V2.0
                """);
        // 注册标签页面
        JaySenSuiteTab jaysenSuiteTab = new JaySenSuiteTab(montoyaApi);
        montoyaApi.userInterface().registerSuiteTab("JaySenWxapkg", jaysenSuiteTab.getUiComponent());
    }
}