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
import burp.api.montoya.MontoyaApi;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.io.File;
import java.util.*;
import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * 适配 Burp Montoya API 的面板类（文件夹选择+自动扫描所有wxapkg+批量解析+配置自动保存）
 */
public class JaySenSuiteTab {
    // ========== UI成员变量 ==========
    private JTable appInfoTable;      // 小程序信息表格
    private JTable apiTable;          // API结果表格
    private JTable sensitiveTable;    // 敏感信息表格
    private JTextField folderPathField; // 文件夹路径输入框
    // 自定义配置输入框
    private JTextArea apiRegexArea;         // API提取正则
    private JTextArea sensitiveRegexArea;   // 敏感信息正则
    private JTextField suffixBlacklistField;// 后缀黑名单
    private JTextField prefixBlacklistField; // 接口前缀过滤黑名单
    private JTextField defaultWxapkgPathField; // Wxapkg默认打开路径
    MontoyaApi montoyaApi;
    public JaySenSuiteTab(MontoyaApi montoyaApi) {
        this.montoyaApi = montoyaApi;
    }
    // ========== 核心方法：返回UI组件 ==========
    public Component getUiComponent() {
        // 1. 先加载保存的配置（初始化UI用）
        Config.SavedConfig savedConfig = Config.loadConfigFile();

        // 2. 主面板（左右分割布局）
        JSplitPane mainSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        mainSplitPane.setDividerLocation(800);
        mainSplitPane.setDividerSize(5);

        // ========== 左侧：结果展示区 ==========
        JPanel leftPanel = new JPanel();
        leftPanel.setLayout(new BoxLayout(leftPanel, BoxLayout.Y_AXIS));
        leftPanel.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15));
        leftPanel.setBackground(Color.WHITE);

        // 左侧标题区
        JLabel titleLabel = new JLabel("JaySenWxapkg");
        titleLabel.setFont(new Font("Microsoft YaHei", Font.BOLD, 24));
        titleLabel.setForeground(new Color(0, 114, 187));
        titleLabel.setAlignmentX(Component.CENTER_ALIGNMENT);

        JLabel subTitleLabel = new JLabel("Wxapkg 解析工具（配置自动保存）");
        subTitleLabel.setFont(new Font("Microsoft YaHei", Font.PLAIN, 16));
        subTitleLabel.setForeground(Color.GRAY);
        subTitleLabel.setAlignmentX(Component.CENTER_ALIGNMENT);

        JSeparator separator = new JSeparator();
        separator.setMaximumSize(new Dimension(Integer.MAX_VALUE, 2));
        separator.setForeground(new Color(220, 220, 220));
        separator.setAlignmentX(Component.CENTER_ALIGNMENT);

        // 左侧功能区（文件夹选择+解析）
        JPanel funcPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 20, 20));
        funcPanel.setBackground(Color.WHITE);
        folderPathField = new JTextField(40);
        setPlaceholder(folderPathField, "请选择小程序目录（自动扫描所有wxapkg）");

        // 文件夹选择按钮
        JButton selectFolderBtn = new JButton("选择文件夹");
        selectFolderBtn.setBackground(new Color(0, 114, 187));
        selectFolderBtn.setForeground(Color.WHITE);
        selectFolderBtn.setBorderPainted(false);
        selectFolderBtn.setFocusPainted(false);
        selectFolderBtn.addActionListener(e -> {
            JFileChooser folderChooser = new JFileChooser();
            folderChooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
            // 默认打开微信小程序缓存目录
            String configDefaultPath = defaultWxapkgPathField.getText().trim();
            File defaultDir = new File(configDefaultPath);
            if (!defaultDir.exists() || !defaultDir.isDirectory()) {
                // 配置路径无效时，回退到原默认路径
                defaultDir = new File(System.getProperty("user.home") + "\\AppData\\Roaming\\Tencent\\xwechat\\radium\\Applet\\packages\\");
                if (!defaultDir.exists()) {
                    defaultDir = new File(System.getProperty("user.home"));
                }
            }
            folderChooser.setCurrentDirectory(defaultDir);
//            if (defaultDir.exists() && defaultDir.isDirectory()) {
//                folderChooser.setCurrentDirectory(defaultDir);
//            } else {
//                folderChooser.setCurrentDirectory(new File(System.getProperty("user.home")));
//            }
            int result = folderChooser.showOpenDialog(leftPanel);
            if (result == JFileChooser.APPROVE_OPTION) {
                File selectedFolder = folderChooser.getSelectedFile();
                folderPathField.setText(selectedFolder.getAbsolutePath());
                folderPathField.setForeground(Color.BLACK);
            }
        });
        // 添加打开文件功能
        JButton openBrowserBtn = new JButton("打开文件浏览器");
        openBrowserBtn.setBackground(new Color(0, 114, 187));
        openBrowserBtn.setForeground(Color.WHITE);
        openBrowserBtn.setBorderPainted(false);
        openBrowserBtn.setFocusPainted(false);
        openBrowserBtn.setEnabled(false); // 初始不可用（反编译后启用）
        openBrowserBtn.addActionListener(e1 -> {
            String outputDir = System.getProperty("user.home") + File.separator +".burp" + File.separator + "JaySenWxapkgOutput";
            new WxapkgFileBrowser(outputDir,montoyaApi).setVisible(true);
        });
        // 解析按钮（核心：先保存配置，再解析）
        JButton parseBtn = new JButton("批量解析所有wxapkg");
        parseBtn.setBackground(new Color(0, 114, 187));
        parseBtn.setForeground(Color.WHITE);
        parseBtn.setBorderPainted(false);
        parseBtn.setFocusPainted(false);
        parseBtn.addActionListener(e -> {
            // 防止重复点击：立即禁用按钮并显示加载状态
            parseBtn.setEnabled(false);
            parseBtn.setText("⏳ 正在解析中...");
            parseBtn.setBackground(new Color(150, 150, 150));
            // 第一步：强制保存当前UI配置到JSON
            saveCurrentUiConfig();

            // 第二步：校验文件夹路径
            String folderPath = folderPathField.getText().trim();
            if (folderPath.isEmpty() || folderPath.equals("请选择小程序目录（自动扫描所有wxapkg）")) {
                JOptionPane.showMessageDialog(leftPanel, "请选择小程序目录！", "提示", JOptionPane.WARNING_MESSAGE);
                resetParseBtn(parseBtn);
                return;
            }
            File targetFolder = new File(folderPath);
            if (!targetFolder.exists() || !targetFolder.isDirectory()) {
                JOptionPane.showMessageDialog(leftPanel, "选择的路径不是有效文件夹！", "错误", JOptionPane.ERROR_MESSAGE);
                resetParseBtn(parseBtn);
                return;
            }

            // 第三步：扫描所有wxapkg文件
            List<File> wxapkgFiles = scanWxapkgFiles(targetFolder);
            if (wxapkgFiles.isEmpty()) {
                JOptionPane.showMessageDialog(leftPanel, "该目录下未找到任何wxapkg文件！", "提示", JOptionPane.INFORMATION_MESSAGE);
                resetParseBtn(parseBtn);
                return;
            }

            // 第四步：读取UI配置（转换为解析所需格式）
            Pattern customApiPattern = null;
            Map<String, Pattern> customSensitivePatterns = new HashMap<>();
            Set<String> suffixBlacklist = new HashSet<>();

            // 解析API正则
            try {
                String apiRegex = apiRegexArea.getText().trim();
                if (!apiRegex.isEmpty()) {
                    customApiPattern = Pattern.compile(apiRegex);
                } else {
                    customApiPattern = Config.DEFAULT_API_PATTERN;
                }
            } catch (PatternSyntaxException ex) {
                JOptionPane.showMessageDialog(leftPanel, "API提取正则格式错误：" + ex.getMessage(), "错误", JOptionPane.ERROR_MESSAGE);
                resetParseBtn(parseBtn);
                return;
            }

            // 解析敏感信息正则
            try {
                String sensitiveText = sensitiveRegexArea.getText().trim();
                Map<String, String> sensitiveMap = Config.parseSensitiveTextToMap(sensitiveText);
                for (Map.Entry<String, String> entry : sensitiveMap.entrySet()) {
                    customSensitivePatterns.put(entry.getKey(), Pattern.compile(entry.getValue()));
                }
            } catch (PatternSyntaxException ex) {
                JOptionPane.showMessageDialog(leftPanel, "敏感信息正则格式错误：" + ex.getMessage(), "错误", JOptionPane.ERROR_MESSAGE);
                resetParseBtn(parseBtn);
                return;
            }

            // 解析后缀黑名单
            String suffixText = suffixBlacklistField.getText().trim();
            suffixBlacklist = Config.parseSuffixTextToSet(suffixText);
            // 解析前缀黑名单
            String prefixText = prefixBlacklistField.getText().trim();
            Set<String> prefixBlacklist = Config.parsePrefixTextToSet(prefixText);
            // 第五步：清空历史结果
            ((DefaultTableModel) appInfoTable.getModel()).setRowCount(0);
            ((DefaultTableModel) apiTable.getModel()).setRowCount(0);
            ((DefaultTableModel) sensitiveTable.getModel()).setRowCount(0);

            // 第六步：异步批量解析
            Pattern finalCustomApiPattern = customApiPattern;
            Set<String> finalSuffixBlacklist = suffixBlacklist;
            new SwingWorker<Void, WxAppletDecompiler>() {
                @Override
                protected Void doInBackground() throws Exception {
                    String outputDir = System.getProperty("user.home") + File.separator +".burp" + File.separator + "JaySenWxapkgOutput";
                    for (File wxapkgFile : wxapkgFiles) {
                        WxAppletDecompiler decompiler = new WxAppletDecompiler(
                                wxapkgFile.getAbsolutePath(),
                                outputDir,
                                5,
                                finalCustomApiPattern,
                                customSensitivePatterns,
                                finalSuffixBlacklist,
                                prefixBlacklist
                        );
                        decompiler.execute();
                        publish(decompiler);
                    }
                    return null;
                }

                @Override
                protected void process(List<WxAppletDecompiler> chunks) {
                    for (WxAppletDecompiler decompiler : chunks) {
                        String pkgType = decompiler.getPackageType();
                        String pkgPath = decompiler.getAppInfoList().get(0).getValue().contains("解包wxapkg文件")
                                ? decompiler.getAppInfoList().get(0).getValue().split("：")[1]
                                : decompiler.getAppInfoList().get(1).getValue();

                        // 填充小程序信息
                        DefaultTableModel appModel = (DefaultTableModel) appInfoTable.getModel();
                        appModel.addRow(new Object[]{"=== " + pkgType + " ===", pkgPath});
                        for (WxAppletDecompiler.AppInfo appInfo : decompiler.getAppInfoList()) {
                            appModel.addRow(new Object[]{appInfo.getKey(), appInfo.getValue()});
                        }
                        appModel.addRow(new Object[]{"---", "---"});

                        // 填充API结果（去重+按字母排序）
                        DefaultTableModel apiModel = (DefaultTableModel) apiTable.getModel();
                        List<WxAppletDecompiler.ApiInfo> apiList = decompiler.getApiInfoList();
                        // 去重：按API路径去重，保留首次出现的
                        Map<String, WxAppletDecompiler.ApiInfo> uniqueMap = new LinkedHashMap<>();
                        for (WxAppletDecompiler.ApiInfo info : apiList) {
                            uniqueMap.putIfAbsent(info.getApi(), info);
                        }
                        // 按API路径字母排序
                        List<WxAppletDecompiler.ApiInfo> sortedList = new ArrayList<>(uniqueMap.values());
                        sortedList.sort(Comparator.comparing(WxAppletDecompiler.ApiInfo::getApi));
                        // 重新编号填充
                        int idx = 1;
                        for (WxAppletDecompiler.ApiInfo apiInfo : sortedList) {
                            apiModel.addRow(new Object[]{idx++, apiInfo.getFile(), apiInfo.getApi()});
                        }

                        // 填充敏感信息
                        DefaultTableModel sensitiveModel = (DefaultTableModel) sensitiveTable.getModel();
                        for (WxAppletDecompiler.SensitiveInfo sensitiveInfo : decompiler.getSensitiveInfoList()) {
                            sensitiveModel.addRow(new Object[]{sensitiveInfo.getFile(), sensitiveInfo.getType(), sensitiveInfo.getContent()});
                        }
                    }
                }

                @Override
                protected void done() {
//                    JOptionPane.showMessageDialog(leftPanel,
//                            "批量解析完成！共处理 " + wxapkgFiles.size() + " 个wxapkg文件",
//                            "完成",
//                            JOptionPane.INFORMATION_MESSAGE
//                    );
                    // 恢复按钮状态
                    resetParseBtn(parseBtn);
                    // 启用文件浏览器按钮
                    openBrowserBtn.setEnabled(true);
                }
            }.execute();
        });

        // 组装功能区
        funcPanel.add(new JLabel("📁 目录："));
        funcPanel.add(folderPathField);
        funcPanel.add(selectFolderBtn);
        funcPanel.add(parseBtn);
        funcPanel.add(openBrowserBtn);

        // 左侧结果展示区（标签页+表格）
        JTabbedPane resultTabbedPane = new JTabbedPane();
        resultTabbedPane.setPreferredSize(new Dimension(780, 450));

        // ① 小程序信息表格
        DefaultTableModel appInfoModel = new DefaultTableModel(new String[]{"配置项", "内容"}, 0);
        appInfoTable = new JTable(appInfoModel);
        appInfoTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        appInfoTable.getColumnModel().getColumn(0).setPreferredWidth(150);
        appInfoTable.getColumnModel().getColumn(1).setPreferredWidth(600);
        resultTabbedPane.addTab("小程序信息", new JScrollPane(appInfoTable));

        // ② API提取结果表格（+右键菜单+一键复制）
        DefaultTableModel apiTableModel = new DefaultTableModel(new String[]{"序号", "文件", "API接口"}, 0);
        apiTable = new JTable(apiTableModel);
        apiTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        apiTable.getColumnModel().getColumn(0).setPreferredWidth(50);
        apiTable.getColumnModel().getColumn(1).setPreferredWidth(200);
        apiTable.getColumnModel().getColumn(2).setPreferredWidth(500);

        // 添加右键菜单：发送选中接口至AI参数智能推测页面
        JPopupMenu apiTablePopup = new JPopupMenu();
        JMenuItem sendToAiItem = new JMenuItem("发送选中接口至AI参数智能推测页面");
        sendToAiItem.setFont(new Font("Microsoft YaHei", Font.PLAIN, 13));
        sendToAiItem.addActionListener(e -> {
            int[] selectedRows = apiTable.getSelectedRows();
            if (selectedRows.length == 0) {
                JOptionPane.showMessageDialog(leftPanel, "请先在表格中选择至少一条API记录！", "提示", JOptionPane.WARNING_MESSAGE);
                return;
            }
            DefaultTableModel model = (DefaultTableModel) apiTable.getModel();
            List<String[]> apiDataList = new ArrayList<>();
            for (int row : selectedRows) {
                Object apiObj = model.getValueAt(row, 2); // 第3列：API接口
                Object fileObj = model.getValueAt(row, 1); // 第2列：文件
                if (apiObj != null) {
                    String apiPath = apiObj.toString().trim();
                    String sourceFile = fileObj != null ? fileObj.toString().trim() : "";
                    apiDataList.add(new String[]{apiPath, sourceFile});
                }
            }
            if (apiDataList.isEmpty()) {
                JOptionPane.showMessageDialog(leftPanel, "未获取到有效的API数据！", "提示", JOptionPane.WARNING_MESSAGE);
                return;
            }
            // 发送至AI参数推测页面
            AiParamInferTab aiTab = AiParamInferTab.getInstance();
            if (aiTab != null) {
                aiTab.addApis(apiDataList);
//                JOptionPane.showMessageDialog(leftPanel,
//                        "已发送 " + apiDataList.size() + " 个接口至【AI参数推测】页面！",
//                        "发送成功", JOptionPane.INFORMATION_MESSAGE);
            } else {
                JOptionPane.showMessageDialog(leftPanel, "AI参数推测页面未初始化，请先打开该Tab！", "错误", JOptionPane.ERROR_MESSAGE);
            }
        });
        apiTablePopup.add(sendToAiItem);
        apiTable.setComponentPopupMenu(apiTablePopup);

        JPanel apiPanel = new JPanel(new BorderLayout());
        apiPanel.add(new JScrollPane(apiTable), BorderLayout.CENTER);
        JButton copyApiBtn = new JButton("一键复制API接口");
        copyApiBtn.addActionListener(e -> {
            StringBuilder apiSb = new StringBuilder();
            DefaultTableModel model = (DefaultTableModel) apiTable.getModel();
            for (int i = 0; i < model.getRowCount(); i++) {
                apiSb.append(model.getValueAt(i, 2)).append("\n");
            }
            StringSelection selection = new StringSelection(apiSb.toString().trim());
            Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
            clipboard.setContents(selection, null);
            JOptionPane.showMessageDialog(apiPanel, "已复制所有API接口到剪贴板！", "提示", JOptionPane.INFORMATION_MESSAGE);
        });
        apiPanel.add(copyApiBtn, BorderLayout.SOUTH);
        resultTabbedPane.addTab("API提取结果", apiPanel);

        // ③ 敏感信息表格
        DefaultTableModel sensitiveTableModel = new DefaultTableModel(new String[]{"文件", "类型", "泄露内容"}, 0);
        sensitiveTable = new JTable(sensitiveTableModel);
        sensitiveTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        sensitiveTable.getColumnModel().getColumn(0).setPreferredWidth(300);
        sensitiveTable.getColumnModel().getColumn(1).setPreferredWidth(150);
        sensitiveTable.getColumnModel().getColumn(2).setPreferredWidth(300);
        resultTabbedPane.addTab("敏感信息", new JScrollPane(sensitiveTable));

        // 组装左侧面板
        leftPanel.add(titleLabel);
        leftPanel.add(Box.createVerticalStrut(5));
        leftPanel.add(subTitleLabel);
        leftPanel.add(Box.createVerticalStrut(10));
        leftPanel.add(separator);
        leftPanel.add(Box.createVerticalStrut(20));
        leftPanel.add(funcPanel);
        leftPanel.add(Box.createVerticalStrut(10));
        leftPanel.add(resultTabbedPane);

        // ========== 右侧：自定义配置区（带自动保存监听） ==========
        JPanel rightPanel = new JPanel();
        rightPanel.setLayout(new BoxLayout(rightPanel, BoxLayout.Y_AXIS));
        rightPanel.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15));
        rightPanel.setBackground(Color.WHITE);
        rightPanel.setPreferredSize(new Dimension(400, 600));

        // 配置区标题
        JLabel configTitle = new JLabel("自定义解析配置（修改自动保存）");
        configTitle.setFont(new Font("Microsoft YaHei", Font.BOLD, 18));
        configTitle.setForeground(new Color(0, 114, 187));
        configTitle.setAlignmentX(Component.CENTER_ALIGNMENT);

        JSeparator configSep = new JSeparator();
        configSep.setMaximumSize(new Dimension(Integer.MAX_VALUE, 2));
        configSep.setForeground(new Color(220, 220, 220));
        configSep.setAlignmentX(Component.CENTER_ALIGNMENT);
        // 添加Wxapkg路径配置框
        JPanel defaultPathPanel = new JPanel(new BorderLayout());
        defaultPathPanel.setBorder(BorderFactory.createTitledBorder("wxapkg默认打开路径"));
        // 加载保存的配置，无则用默认路径
        String defaultPath = savedConfig.getwxapkgPath() != null
                ? savedConfig.getwxapkgPath()
                : System.getProperty("user.home") + "\\AppData\\Roaming\\Tencent\\xwechat\\radium\\Applet\\packages\\";
        defaultWxapkgPathField = new JTextField(defaultPath);
        // 添加自动保存监听
        defaultWxapkgPathField.getDocument().addDocumentListener(new ConfigChangeListener());
        defaultPathPanel.add(new JScrollPane(defaultWxapkgPathField), BorderLayout.CENTER);

        // 1. API提取正则配置（初始化+添加修改监听）
        JPanel apiRegexPanel = new JPanel(new BorderLayout());
        apiRegexPanel.setBorder(BorderFactory.createTitledBorder("API提取正则（留空用默认）"));
        apiRegexArea = new JTextArea(savedConfig.getApiRegex(), 3, 30); // 加载保存的配置
        apiRegexArea.setLineWrap(true);
        apiRegexArea.setWrapStyleWord(true);
        // 添加修改监听：内容变化自动保存
        apiRegexArea.getDocument().addDocumentListener(new ConfigChangeListener());
        apiRegexPanel.add(new JScrollPane(apiRegexArea), BorderLayout.CENTER);

        // 2. 敏感信息正则配置（初始化+添加修改监听）
        JPanel sensitiveRegexPanel = new JPanel(new BorderLayout());
        sensitiveRegexPanel.setBorder(BorderFactory.createTitledBorder("敏感信息正则（格式：类型:正则，一行一个）"));
        sensitiveRegexArea = new JTextArea(Config.convertSensitiveMapToText(savedConfig.getSensitiveRegexMap()), 10, 30); // 加载保存的配置
        sensitiveRegexArea.setLineWrap(true);
        sensitiveRegexArea.setWrapStyleWord(true);
        // 添加修改监听：内容变化自动保存
        sensitiveRegexArea.getDocument().addDocumentListener(new ConfigChangeListener());
        sensitiveRegexPanel.add(new JScrollPane(sensitiveRegexArea), BorderLayout.CENTER);

        // 3. 接口前缀过滤黑名单配置
        JPanel prefixBlackPanel = new JPanel(new BorderLayout());
        prefixBlackPanel.setBorder(BorderFactory.createTitledBorder("接口关键词过滤黑名单（主要过滤前端文件路径，逗号分隔，如：/pages,/components）"));
        prefixBlacklistField = new JTextField(Config.convertPrefixSetToText(savedConfig.getPrefixBlacklist())); // 加载保存的配置
        prefixBlacklistField.getDocument().addDocumentListener(new ConfigChangeListener()); // 自动保存监听
        prefixBlackPanel.add(prefixBlacklistField, BorderLayout.CENTER);

        // 4. 后缀黑名单配置（初始化+添加修改监听）
        JPanel suffixBlackPanel = new JPanel(new BorderLayout());
        suffixBlackPanel.setBorder(BorderFactory.createTitledBorder("接口后缀过滤（逗号分隔，如：js,wxml,wxss）"));
        suffixBlacklistField = new JTextField(Config.convertSuffixSetToText(savedConfig.getSuffixBlacklist())); // 加载保存的配置
        // 添加修改监听：内容变化自动保存
        suffixBlacklistField.getDocument().addDocumentListener(new ConfigChangeListener());
        suffixBlackPanel.add(suffixBlacklistField, BorderLayout.CENTER);

        // 组装右侧面板
        rightPanel.add(configTitle);
        rightPanel.add(Box.createVerticalStrut(10));
        rightPanel.add(configSep);
        rightPanel.add(Box.createVerticalStrut(20));
        rightPanel.add(defaultPathPanel);
        rightPanel.add(Box.createVerticalStrut(15));
        rightPanel.add(apiRegexPanel);
        rightPanel.add(Box.createVerticalStrut(15));
        rightPanel.add(sensitiveRegexPanel);
        rightPanel.add(Box.createVerticalStrut(15));
        rightPanel.add(prefixBlackPanel);
        rightPanel.add(Box.createVerticalStrut(15));
        rightPanel.add(suffixBlackPanel);
        rightPanel.add(Box.createVerticalStrut(20));

        // 一键恢复默认配置按钮
        JButton resetDefaultBtn = new JButton("恢复默认配置");
        resetDefaultBtn.setBackground(new Color(0, 114, 187));
        resetDefaultBtn.setForeground(Color.WHITE);
        resetDefaultBtn.setBorderPainted(false);
        resetDefaultBtn.setFocusPainted(false);
        resetDefaultBtn.setFont(new Font("Microsoft YaHei", Font.PLAIN, 13));
        resetDefaultBtn.setMaximumSize(new Dimension(Integer.MAX_VALUE, 36));
        resetDefaultBtn.setAlignmentX(Component.CENTER_ALIGNMENT);
        resetDefaultBtn.addActionListener(e -> resetToDefaultConfig());
        rightPanel.add(resetDefaultBtn);

        // 组装主分割面板
        mainSplitPane.setLeftComponent(leftPanel);
        mainSplitPane.setRightComponent(rightPanel);

        // 顶层JTabbedPane：包含 JaySenWxapkg 和 AI参数推测 两个二级标签页
        JTabbedPane topTabbedPane = new JTabbedPane();
        topTabbedPane.addTab("解析Wxapkg", mainSplitPane);
        AiParamInferTab aiTab = new AiParamInferTab(montoyaApi);
        topTabbedPane.addTab("AI参数推测", aiTab.getUiComponent());

        return topTabbedPane;
    }

    // ========== 内部类：配置修改监听器（修改即保存） ==========
    private class ConfigChangeListener implements DocumentListener {
        @Override
        public void insertUpdate(DocumentEvent e) { saveCurrentUiConfig(); }
        @Override
        public void removeUpdate(DocumentEvent e) { saveCurrentUiConfig(); }
        @Override
        public void changedUpdate(DocumentEvent e) { saveCurrentUiConfig(); }
    }

    // ========== 核心方法：保存当前UI配置到JSON ==========
    private void saveCurrentUiConfig() {
        try {
            // 1. 读取UI内容
            String apiRegex = apiRegexArea.getText().trim();
            Map<String, String> sensitiveMap = Config.parseSensitiveTextToMap(sensitiveRegexArea.getText().trim());
            Set<String> suffixSet = Config.parseSuffixTextToSet(suffixBlacklistField.getText().trim());
            Set<String> prefixSet = Config.parsePrefixTextToSet(prefixBlacklistField.getText().trim());
            String wxapkgPath = defaultWxapkgPathField.getText().trim();

            // 2. 调用Config保存方法
            Config.saveConfigFile(apiRegex, sensitiveMap, suffixSet,prefixSet,wxapkgPath);
        } catch (Exception e) {
            // 静默失败，不弹框干扰用户
        }
    }

    // ========== 一键恢复默认配置 ==========
    private void resetToDefaultConfig() {
        int choice = JOptionPane.showConfirmDialog(null,
                "确认恢复默认配置？当前所有配置将被覆盖。",
                "确认恢复", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
        if (choice != JOptionPane.YES_OPTION) return;

        // 恢复所有字段为默认值
        apiRegexArea.setText(Config.DEFAULT_API_PATTERN.pattern());
        sensitiveRegexArea.setText(Config.convertSensitiveMapToText(null));
        suffixBlacklistField.setText(Config.convertSuffixSetToText(null));
        prefixBlacklistField.setText(Config.convertPrefixSetToText(Config.DEFAULT_PREFIX_BLACKLIST));
        defaultWxapkgPathField.setText(Config.DEFAULT_WXAPKGPATH);

        // DocumentListener会自动触发saveCurrentUiConfig()保存到文件
        JOptionPane.showMessageDialog(null, "已恢复默认配置并保存！", "完成", JOptionPane.INFORMATION_MESSAGE);
    }

    // ========== 恢复解析按钮状态 ==========
    private void resetParseBtn(JButton btn) {
        btn.setEnabled(true);
        btn.setText("批量解析所有wxapkg");
        btn.setBackground(new Color(0, 114, 187));
    }

    // ========== 工具方法：扫描目录下所有wxapkg文件（递归） ==========
    private List<File> scanWxapkgFiles(File rootDir) {
        List<File> wxapkgFiles = new ArrayList<>();
        if (!rootDir.exists() || !rootDir.isDirectory()) {
            return wxapkgFiles;
        }
        File[] files = rootDir.listFiles();
        if (files == null) {
            return wxapkgFiles;
        }
        for (File file : files) {
            if (file.isDirectory()) {
                wxapkgFiles.addAll(scanWxapkgFiles(file));
            } else if (file.isFile() && file.getName().toLowerCase().endsWith(".wxapkg")) {
                wxapkgFiles.add(file);
            }
        }
        return wxapkgFiles;
    }

    // ========== 工具方法：给JTextField添加占位符 ==========
    private void setPlaceholder(JTextField textField, String placeholder) {
        textField.putClientProperty("JTextField.placeholder", placeholder);
        textField.addFocusListener(new java.awt.event.FocusAdapter() {
            @Override
            public void focusGained(java.awt.event.FocusEvent evt) {
                if (textField.getText().equals(placeholder)) {
                    textField.setText("");
                    textField.setForeground(Color.BLACK);
                }
            }
            @Override
            public void focusLost(java.awt.event.FocusEvent evt) {
                if (textField.getText().isEmpty()) {
                    textField.setText(placeholder);
                    textField.setForeground(Color.GRAY);
                }
            }
        });
        textField.setText(placeholder);
        textField.setForeground(Color.GRAY);
    }
}