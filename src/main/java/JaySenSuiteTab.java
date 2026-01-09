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
            String userHome = System.getProperty("user.home");
            File defaultDir = new File(userHome + "\\AppData\\Roaming\\Tencent\\xwechat\\radium\\Applet\\packages\\");
            if (defaultDir.exists() && defaultDir.isDirectory()) {
                folderChooser.setCurrentDirectory(defaultDir);
            } else {
                folderChooser.setCurrentDirectory(new File(userHome));
            }
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
            // 第一步：强制保存当前UI配置到JSON
            saveCurrentUiConfig();

            // 第二步：校验文件夹路径
            String folderPath = folderPathField.getText().trim();
            if (folderPath.isEmpty() || folderPath.equals("请选择小程序目录（自动扫描所有wxapkg）")) {
                JOptionPane.showMessageDialog(leftPanel, "请选择小程序目录！", "提示", JOptionPane.WARNING_MESSAGE);
                return;
            }
            File targetFolder = new File(folderPath);
            if (!targetFolder.exists() || !targetFolder.isDirectory()) {
                JOptionPane.showMessageDialog(leftPanel, "选择的路径不是有效文件夹！", "错误", JOptionPane.ERROR_MESSAGE);
                return;
            }

            // 第三步：扫描所有wxapkg文件
            List<File> wxapkgFiles = scanWxapkgFiles(targetFolder);
            if (wxapkgFiles.isEmpty()) {
                JOptionPane.showMessageDialog(leftPanel, "该目录下未找到任何wxapkg文件！", "提示", JOptionPane.INFORMATION_MESSAGE);
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

                        // 填充API结果
                        DefaultTableModel apiModel = (DefaultTableModel) apiTable.getModel();
                        for (WxAppletDecompiler.ApiInfo apiInfo : decompiler.getApiInfoList()) {
                            apiModel.addRow(new Object[]{apiInfo.getIndex(), apiInfo.getFile(), apiInfo.getApi()});
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
                    JOptionPane.showMessageDialog(leftPanel,
                            "批量解析完成！共处理 " + wxapkgFiles.size() + " 个wxapkg文件",
                            "完成",
                            JOptionPane.INFORMATION_MESSAGE
                    );
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

        // ② API提取结果表格（+一键复制）
        DefaultTableModel apiTableModel = new DefaultTableModel(new String[]{"序号", "文件", "API接口"}, 0);
        apiTable = new JTable(apiTableModel);
        apiTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        apiTable.getColumnModel().getColumn(0).setPreferredWidth(50);
        apiTable.getColumnModel().getColumn(1).setPreferredWidth(200);
        apiTable.getColumnModel().getColumn(2).setPreferredWidth(500);
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
        rightPanel.add(apiRegexPanel);
        rightPanel.add(Box.createVerticalStrut(15));
        rightPanel.add(sensitiveRegexPanel);
        rightPanel.add(Box.createVerticalStrut(15));
        rightPanel.add(prefixBlackPanel);
        rightPanel.add(Box.createVerticalStrut(15));
        rightPanel.add(suffixBlackPanel);

        // 组装主分割面板
        mainSplitPane.setLeftComponent(leftPanel);
        mainSplitPane.setRightComponent(rightPanel);

        return mainSplitPane;
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

            // 2. 调用Config保存方法
            Config.saveConfigFile(apiRegex, sensitiveMap, suffixSet,prefixSet);
        } catch (Exception e) {
            // 静默失败，不弹框干扰用户
        }
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