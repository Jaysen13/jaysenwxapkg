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
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import okhttp3.*;

import javax.swing.*;
import javax.swing.event.ListSelectionEvent;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.file.Files;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static java.lang.Integer.parseInt;

/**
 * AI参数智能推测 Tab
 * 左栏：API列表 + 历史请求详情 | 右栏：Prompt + 结果 + AI配置 + 日志
 */
public class AiParamInferTab {

    // ========== 单例 ==========
    private static AiParamInferTab instance;

    public static AiParamInferTab getInstance() {
        return instance;
    }

    // ========== UI组件 ==========
    private JTable apiListTable;
    private DefaultTableModel apiListModel;
    private JTextArea promptArea;
    private JTextArea resultArea;
    private JTextArea historyDetailArea;
    private JTextField apiKeyField;
    private JTextField modelUrlField;
    private JTextField modelNameField;
    private JTextField timeoutField;
    private JTextField contextLengthField;
    private JTextField extraHeadersField;
    private JTextField domainField;
    private JComboBox<String> presetField;
    private JLabel statusLabel;
    private MontoyaApi montoyaApi;

    // ========== 数据模型 ==========
    private final List<ApiEntry> apiEntries = new ArrayList<>();
    private final AtomicInteger idCounter = new AtomicInteger(0);
    // ========== 缓存 ==========
    private List<ProxyHttpRequestResponse> cachedHistory; // 缓存Burp历史
    private Map<String, List<ProxyHttpRequestResponse>> domainHistoryCache = new HashMap<>();

    // ========== 默认Prompt模板 ==========
    private static final String DEFAULT_PROMPT_TEMPLATE =
            "你是一个资深后端开发/安全工程师。请根据【已观测接口】的命名风格和参数习惯，推测【待推测接口】列表中每个API的请求参数。\n\n" +
            "===== 推测示例（请严格按此格式输出） =====\n" +
            "【接口路径】/api/order/list\n" +
            "  功能描述: 获取订单列表，支持分页和状态筛选\n" +
            "  请求方式: GET\n" +
            "  推测参数:\n" +
            "    - page | int | 是 | 页码 | 1\n" +
            "    - size | int | 是 | 每页条数 | 10\n" +
            "    - status | string | 否 | 订单状态筛选 | pending\n" +
            "    - keyword | string | 否 | 搜索关键词 | 手机\n" +
            "  完整请求示例:\n" +
            "    ```\n" +
            "    GET /api/order/list?page=1&size=10&status=pending&keyword=手机 HTTP/1.1\n" +
            "    Host: api.example.com\n" +
            "    Authorization: Bearer <token>\n" +
            "    Content-Type: application/json;charset=UTF-8\n" +
            "    ```\n" +
            "\n" +
            "【接口路径】/api/user/login\n" +
            "  功能描述: 用户登录接口，通过账号密码获取认证令牌\n" +
            "  请求方式: POST\n" +
            "  推测参数:\n" +
            "    - username | string | 是 | 用户名/手机号 | 13800138000\n" +
            "    - password | string | 是 | 密码 | 123456\n" +
            "    - captcha | string | 否 | 验证码 | ab12\n" +
            "  完整请求示例:\n" +
            "    ```\n" +
            "    POST /api/user/login HTTP/1.1\n" +
            "    Host: api.example.com\n" +
            "    Content-Type: application/json;charset=UTF-8\n" +
            "    \n" +
            "    {\"username\":\"13800138000\",\"password\":\"123456\"}\n" +
            "    ```\n" +
            "===== 示例结束 =====\n\n" +
            "分析原则：\n" +
            "1. 【最高优先级】若接口附带了\"源码上下文\"，优先从中提取参数名、请求方法和参数值，源码中的变量名和字面量是最准确的\n" +
            "2. 其次参考【已观测接口】的参数命名风格（驼峰/下划线/拼音等）进行推测\n" +
            "3. 根据接口路径语义推测业务参数（如 /order/list → 分页+状态，/user/login → 账号密码）\n" +
            "4. 若已观测接口使用某个特定参数名（如 current 而非 page），请保持一致\n" +
            "5. Body参数使用JSON格式，URL参数使用查询字符串\n" +
            "6. 【重要】观察已观测接口的URL前缀模式（如 /shop/api/...），若待推测接口缺少该前缀，请在推测结果中补全为一致的前缀路径\n\n" +
            "====================\n" +
            "【待推测接口】（需要你推测参数的接口列表）\n" +
            "{api_list}\n\n" +
            "====================\n" +
            "【已观测接口】（学习命名风格和参数习惯，不要推测这些接口）\n" +
            "{param_refs}\n\n" +
            "注意：只推测【待推测接口】中的接口，每个接口输出一个完整的上述格式块。";

    // ========== AI配置默认值 ==========
    private static final String DEFAULT_MODEL_URL = "https://api.deepseek.com/chat/completions";
    private static final String DEFAULT_MODEL_NAME = "deepseek-chat";
    private static final String DEFAULT_TIMEOUT = "60";
    private static final String DEFAULT_CONTEXT_LENGTH = "24576";
    private static final String CUSTOM_PRESET = "Custom";
    private static final String CHAT_COMPLETIONS_SUFFIX = "/chat/completions";
    private static final String MINI_MAX_PROVIDER = "MiniMax";
    private static final String MINI_MAX_M3 = "MiniMax-M3";
    private static final String MINI_MAX_M27 = "MiniMax-M2.7";
    private static final String MINI_MAX_GLOBAL_BASE_URL = "https://api.minimax.io/v1";
    private static final String MINI_MAX_CHINA_BASE_URL = "https://api.minimaxi.com/v1";
    private static final Map<String, ChatPreset> CHAT_PRESETS = buildChatPresets();

    // ========== 中文字体 ==========
    private static final Font CN_FONT = new Font("Microsoft YaHei", Font.PLAIN, 12);
    private static final Font CN_BOLD_FONT = new Font("Microsoft YaHei", Font.BOLD, 12);
    private static final String LOG_DATE_FORMAT = "yyyy-MM-dd HH:mm:ss";
    private static final File LOG_FILE = new File(System.getProperty("user.home") + "\\.burp\\jaysenwxapkg\\jaysenwxapkg.log");

    record ChatPreset(String providerName, String modelName, String modelUrl, String contextLength) {}

    public AiParamInferTab(MontoyaApi montoyaApi) {
        this.montoyaApi = montoyaApi;
        instance = this;
    }

    // ========== 核心：返回UI组件 ==========
    public Component getUiComponent() {
        JSplitPane mainSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        mainSplit.setDividerLocation(700);
        mainSplit.setDividerSize(5);

        JPanel leftPanel = buildLeftPanel();
        JPanel rightPanel = buildRightPanel();

        mainSplit.setLeftComponent(leftPanel);
        mainSplit.setRightComponent(rightPanel);

        return mainSplit;
    }

    // ========== 左栏：API列表 + 历史详情 ==========
    private JPanel buildLeftPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        panel.setBackground(Color.WHITE);

        // 标题 + 域名输入栏
        JPanel northPanel = new JPanel(new BorderLayout(0, 5));
        northPanel.setBackground(Color.WHITE);
        JLabel title = new JLabel("待分析接口列表");
        title.setFont(new Font("Microsoft YaHei", Font.BOLD, 16));
        title.setForeground(new Color(0, 114, 187));
        northPanel.add(title, BorderLayout.NORTH);

        JPanel domainPanel = new JPanel(new BorderLayout(5, 0));
        domainPanel.setBackground(Color.WHITE);
        domainPanel.add(new JLabel("目标域名:"), BorderLayout.WEST);
        domainField = new JTextField("", 30);
        domainField.setFont(CN_FONT);
        domainField.setToolTipText("手动输入域名用于匹配Burp历史请求，如 example.com");
        JButton applyDomainBtn = new JButton("应用");
        applyDomainBtn.setFont(CN_FONT);
        applyDomainBtn.addActionListener(e -> loadHistoryForDomain());
        JPanel domainInputPanel = new JPanel(new BorderLayout(5, 0));
        domainInputPanel.setBackground(Color.WHITE);
        domainInputPanel.add(domainField, BorderLayout.CENTER);
        domainInputPanel.add(applyDomainBtn, BorderLayout.EAST);
        domainPanel.add(domainInputPanel, BorderLayout.CENTER);
        northPanel.add(domainPanel, BorderLayout.SOUTH);

        panel.add(northPanel, BorderLayout.NORTH);

        // 上：API表格 | 下：历史请求详情（JSplitPane）
        JSplitPane centerSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        centerSplit.setDividerLocation(300);
        centerSplit.setDividerSize(4);

        // 上：表格
        apiListModel = new DefaultTableModel(
                new String[]{"序号", "原始API路径", "所属小程序文件", "域名请求数"}, 0) {
            @Override
            public boolean isCellEditable(int row, int column) { return false; }
        };
        apiListTable = new JTable(apiListModel);
        apiListTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        apiListTable.getColumnModel().getColumn(0).setPreferredWidth(50);
        apiListTable.getColumnModel().getColumn(1).setPreferredWidth(280);
        apiListTable.getColumnModel().getColumn(2).setPreferredWidth(150);
        apiListTable.getColumnModel().getColumn(3).setPreferredWidth(100);
        apiListTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);

        // 选中行时自动展示历史详情
        apiListTable.getSelectionModel().addListSelectionListener((ListSelectionEvent e) -> {
            if (!e.getValueIsAdjusting()) {
                loadHistoryDetailForDomain();
            }
        });

        JScrollPane tableScroll = new JScrollPane(apiListTable);
        tableScroll.setBorder(BorderFactory.createTitledBorder("API列表（Shift/Ctrl多选，单击查看历史请求详情）"));
        centerSplit.setTopComponent(tableScroll);

        // 下：历史请求详情
        historyDetailArea = new JTextArea();
        historyDetailArea.setEditable(false);
        historyDetailArea.setLineWrap(true);
        historyDetailArea.setWrapStyleWord(true);
        historyDetailArea.setFont(CN_FONT);
        JScrollPane historyScroll = new JScrollPane(historyDetailArea);
        historyScroll.setBorder(BorderFactory.createTitledBorder("同域名Burp历史请求详情（URL参数+POST参数）"));
        centerSplit.setBottomComponent(historyScroll);

        panel.add(centerSplit, BorderLayout.CENTER);

        // 底部操作按钮区
        JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));
        btnPanel.setBackground(Color.WHITE);

        JButton clearBtn = createButton("清空列表", new Color(180, 60, 60));
        clearBtn.addActionListener(e -> clearApiList());

        JButton refreshHistoryBtn = createButton("刷新Burp历史统计", new Color(0, 114, 187));
        refreshHistoryBtn.addActionListener(e -> refreshHistoryCount());

        JButton sendSelectedBtn = createButton("发送选中至AI", new Color(0, 114, 187));
        sendSelectedBtn.addActionListener(e -> sendSelectedToAI());

        JButton deleteBtn = createButton("删除选中", new Color(150, 50, 50));
        deleteBtn.addActionListener(e -> deleteSelectedApis());

        JButton addManualBtn = createButton("手动新增", new Color(0, 114, 187));
        addManualBtn.addActionListener(e -> addManualApi());

        btnPanel.add(clearBtn);
        btnPanel.add(refreshHistoryBtn);
        btnPanel.add(sendSelectedBtn);
        btnPanel.add(deleteBtn);
        btnPanel.add(addManualBtn);

        statusLabel = new JLabel("就绪，共 0 条待分析接口");
        statusLabel.setFont(CN_FONT);
        statusLabel.setForeground(Color.GRAY);
        JPanel statusPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        statusPanel.setBackground(Color.WHITE);
        statusPanel.add(statusLabel);

        JPanel bottomPanel = new JPanel(new BorderLayout());
        bottomPanel.setBackground(Color.WHITE);
        bottomPanel.add(btnPanel, BorderLayout.NORTH);
        bottomPanel.add(statusPanel, BorderLayout.SOUTH);
        panel.add(bottomPanel, BorderLayout.SOUTH);

        return panel;
    }

    // ========== 右栏：Prompt + 结果 + 日志 + AI配置 ==========
    private JPanel buildRightPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        panel.setBackground(Color.WHITE);

        // ===== Prompt 区域 =====
        JLabel userPromptTitle = new JLabel("User Prompt 模板");
        userPromptTitle.setFont(new Font("Microsoft YaHei", Font.BOLD, 13));
        userPromptTitle.setForeground(new Color(0, 114, 187));
        userPromptTitle.setAlignmentX(Component.LEFT_ALIGNMENT);
        panel.add(userPromptTitle);

        promptArea = new JTextArea(DEFAULT_PROMPT_TEMPLATE, 8, 40);
        promptArea.setLineWrap(true);
        promptArea.setWrapStyleWord(true);
        promptArea.setFont(CN_FONT);
        JScrollPane promptScroll = new JScrollPane(promptArea);
        promptScroll.setBorder(BorderFactory.createTitledBorder("{api_list} 自动替换为接口列表"));
        promptScroll.setMaximumSize(new Dimension(Integer.MAX_VALUE, 140));
        promptScroll.setAlignmentX(Component.LEFT_ALIGNMENT);
        panel.add(promptScroll);
        panel.add(Box.createVerticalStrut(8));

        // ===== AI返回结果 =====
        JLabel resultTitle = new JLabel("AI 返回结果");
        resultTitle.setFont(new Font("Microsoft YaHei", Font.BOLD, 14));
        resultTitle.setForeground(new Color(0, 114, 187));
        resultTitle.setAlignmentX(Component.LEFT_ALIGNMENT);
        panel.add(resultTitle);

        resultArea = new JTextArea(14, 40);
        resultArea.setEditable(false);
        resultArea.setLineWrap(true);
        resultArea.setWrapStyleWord(true);
        resultArea.setFont(CN_FONT);
        JScrollPane resultScroll = new JScrollPane(resultArea);
        resultScroll.setBorder(BorderFactory.createTitledBorder("AI分析结果"));
        resultScroll.setAlignmentX(Component.LEFT_ALIGNMENT);
        panel.add(resultScroll);

        JPanel resultBtnPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 2));
        resultBtnPanel.setBackground(Color.WHITE);
        resultBtnPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        JButton copyBtn = createButton("复制结果", new Color(100, 100, 100));
        copyBtn.addActionListener(e -> {
            Toolkit.getDefaultToolkit().getSystemClipboard()
                    .setContents(new StringSelection(resultArea.getText()), null);
            JOptionPane.showMessageDialog(panel, "已复制！", "提示", JOptionPane.INFORMATION_MESSAGE);
        });
        JButton exportBtn = createButton("导出结果", new Color(100, 100, 100));
        exportBtn.addActionListener(e -> {
            JFileChooser fc = new JFileChooser();
            fc.setSelectedFile(new File("ai_result.txt"));
            if (fc.showSaveDialog(panel) == JFileChooser.APPROVE_OPTION) {
                try { Files.writeString(fc.getSelectedFile().toPath(), resultArea.getText());
                    JOptionPane.showMessageDialog(panel, "导出成功！"); }
                catch (IOException ex) { JOptionPane.showMessageDialog(panel, "失败：" + ex.getMessage()); }
            }
        });
        resultBtnPanel.add(copyBtn);
        resultBtnPanel.add(exportBtn);
        panel.add(resultBtnPanel);
        panel.add(Box.createVerticalStrut(8));

        // ===== AI对话日志按钮 =====
        JPanel logBtnPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 2));
        logBtnPanel.setBackground(Color.WHITE);
        logBtnPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        JButton openLogBtn = createButton("打开AI对话日志目录", new Color(0, 114, 187));
        openLogBtn.addActionListener(e -> openLogDirectory());
        logBtnPanel.add(openLogBtn);
        panel.add(logBtnPanel);
        panel.add(Box.createVerticalStrut(8));

        // ===== AI接口配置 =====
        JLabel configTitle = new JLabel("AI 接口配置");
        configTitle.setFont(new Font("Microsoft YaHei", Font.BOLD, 14));
        configTitle.setForeground(new Color(0, 114, 187));
        configTitle.setAlignmentX(Component.LEFT_ALIGNMENT);
        panel.add(configTitle);

        JPanel configPanel = new JPanel(new GridBagLayout());
        configPanel.setBackground(Color.WHITE);
        configPanel.setBorder(BorderFactory.createTitledBorder("API连接参数"));
        configPanel.setMaximumSize(new Dimension(Integer.MAX_VALUE, 260));
        configPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(2, 5, 2, 5);
        gbc.weightx = 1.0;

        // Provider preset
        gbc.gridx = 0; gbc.gridy = 0; gbc.weightx = 0;
        configPanel.add(new JLabel("Provider preset:"), gbc);
        gbc.gridx = 1; gbc.gridwidth = 2; gbc.weightx = 1.0;
        presetField = new JComboBox<>(buildPresetLabels());
        presetField.setFont(CN_FONT);
        presetField.addActionListener(e -> applySelectedPreset());
        configPanel.add(presetField, gbc);
        gbc.gridx = 3; gbc.gridwidth = 1; gbc.weightx = 0;
        JButton applyPresetBtn = createButton("Apply", new Color(0, 114, 187));
        applyPresetBtn.addActionListener(e -> applySelectedPreset());
        configPanel.add(applyPresetBtn, gbc);

        // API Key
        gbc.gridx = 0; gbc.gridy = 1; gbc.weightx = 0;
        configPanel.add(new JLabel("API Key:"), gbc);
        gbc.gridx = 1; gbc.weightx = 1.0;
        apiKeyField = new JTextField(30);
        apiKeyField.setFont(CN_FONT);
        configPanel.add(apiKeyField, gbc);

        // 模型地址
        gbc.gridx = 0; gbc.gridy = 2; gbc.weightx = 0;
        configPanel.add(new JLabel("API地址:"), gbc);
        gbc.gridx = 1; gbc.weightx = 1.0;
        modelUrlField = new JTextField(DEFAULT_MODEL_URL, 30);
        modelUrlField.setFont(CN_FONT);
        configPanel.add(modelUrlField, gbc);

        // 模型名称
        gbc.gridx = 0; gbc.gridy = 3; gbc.weightx = 0;
        configPanel.add(new JLabel("模型名称:"), gbc);
        gbc.gridx = 1; gbc.weightx = 1.0;
        modelNameField = new JTextField(DEFAULT_MODEL_NAME, 20);
        modelNameField.setFont(CN_FONT);
        configPanel.add(modelNameField, gbc);

        // 请求超时 & 上下文长度（同行）
        gbc.gridx = 0; gbc.gridy = 4; gbc.weightx = 0;
        configPanel.add(new JLabel("超时(秒):"), gbc);
        gbc.gridx = 1; gbc.weightx = 0.5;
        timeoutField = new JTextField(DEFAULT_TIMEOUT, 5);
        timeoutField.setFont(CN_FONT);
        configPanel.add(timeoutField, gbc);

        gbc.gridx = 2; gbc.weightx = 0;
        configPanel.add(new JLabel("上下文长度:"), gbc);
        gbc.gridx = 3; gbc.weightx = 0.5;
        contextLengthField = new JTextField(DEFAULT_CONTEXT_LENGTH, 6);
        contextLengthField.setFont(CN_FONT);
        configPanel.add(contextLengthField, gbc);

        // 额外Headers（适配不同API认证方式）
        gbc.gridx = 0; gbc.gridy = 5; gbc.weightx = 0;
        configPanel.add(new JLabel("额外Headers:"), gbc);
        gbc.gridx = 1; gbc.gridwidth = 3; gbc.weightx = 1.0;
        extraHeadersField = new JTextField("", 30);
        extraHeadersField.setFont(new Font("Consolas", Font.PLAIN, 11));
        JPanel headerHintPanel = new JPanel(new BorderLayout());
        headerHintPanel.setBackground(Color.WHITE);
        headerHintPanel.add(extraHeadersField, BorderLayout.CENTER);
        JLabel hintLabel = new JLabel("  格式: Key1:Value1;Key2:Value2  (如非标准Bearer认证)");
        hintLabel.setFont(new Font("Microsoft YaHei", Font.PLAIN, 10));
        hintLabel.setForeground(Color.GRAY);
        headerHintPanel.add(hintLabel, BorderLayout.SOUTH);
        configPanel.add(headerHintPanel, gbc);

        panel.add(configPanel);

        // ===== 测试AI连接按钮 =====
        JPanel testBtnPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 2));
        testBtnPanel.setBackground(Color.WHITE);
        testBtnPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        JButton testAiBtn = createButton("测试AI连接", new Color(0, 114, 187));
        testAiBtn.addActionListener(e -> testAiConnection());
        testBtnPanel.add(testAiBtn);
        panel.add(testBtnPanel);
        panel.add(Box.createVerticalStrut(8));

        // 初始化时加载已保存的AI配置
        loadAiConfig();

        return panel;
    }

    // ========== 辅助：创建按钮 ==========
    private JButton createButton(String text, Color bgColor) {
        JButton btn = new JButton(text);
        btn.setBackground(bgColor);
        btn.setForeground(Color.WHITE);
        btn.setBorderPainted(false);
        btn.setFocusPainted(false);
        btn.setFont(CN_BOLD_FONT);
        return btn;
    }

    private static String[] buildPresetLabels() {
        String[] labels = new String[CHAT_PRESETS.size() + 1];
        labels[0] = CUSTOM_PRESET;
        int index = 1;
        for (String label : CHAT_PRESETS.keySet()) {
            labels[index++] = label;
        }
        return labels;
    }

    private static Map<String, ChatPreset> buildChatPresets() {
        Map<String, ChatPreset> presets = new LinkedHashMap<>();
        presets.put(MINI_MAX_PROVIDER + " / " + MINI_MAX_M3 + " (Global)", new ChatPreset(MINI_MAX_PROVIDER, MINI_MAX_M3, MINI_MAX_GLOBAL_BASE_URL, "1000000"));
        presets.put(MINI_MAX_PROVIDER + " / " + MINI_MAX_M3 + " (China)", new ChatPreset(MINI_MAX_PROVIDER, MINI_MAX_M3, MINI_MAX_CHINA_BASE_URL, "1000000"));
        presets.put(MINI_MAX_PROVIDER + " / " + MINI_MAX_M27 + " (Global)", new ChatPreset(MINI_MAX_PROVIDER, MINI_MAX_M27, MINI_MAX_GLOBAL_BASE_URL, "204800"));
        presets.put(MINI_MAX_PROVIDER + " / " + MINI_MAX_M27 + " (China)", new ChatPreset(MINI_MAX_PROVIDER, MINI_MAX_M27, MINI_MAX_CHINA_BASE_URL, "204800"));
        return presets;
    }

    static ChatPreset getPreset(String label) {
        return CHAT_PRESETS.get(label);
    }

    private void applySelectedPreset() {
        if (presetField == null) return;
        Object selected = presetField.getSelectedItem();
        if (selected == null) return;
        ChatPreset preset = CHAT_PRESETS.get(selected.toString());
        if (preset == null) return;
        modelUrlField.setText(preset.modelUrl());
        modelNameField.setText(preset.modelName());
        contextLengthField.setText(preset.contextLength());
    }

    private void syncPresetSelection() {
        if (presetField == null) return;
        String modelUrl = modelUrlField.getText().trim();
        String modelName = modelNameField.getText().trim();
        String contextLength = contextLengthField.getText().trim();
        for (Map.Entry<String, ChatPreset> entry : CHAT_PRESETS.entrySet()) {
            ChatPreset preset = entry.getValue();
            if (preset.modelUrl().equals(modelUrl) && preset.modelName().equals(modelName) && preset.contextLength().equals(contextLength)) {
                presetField.setSelectedItem(entry.getKey());
                return;
            }
        }
        presetField.setSelectedItem(CUSTOM_PRESET);
    }

    static String normalizeChatCompletionsUrl(String modelUrl) {
        if (modelUrl == null) return "";
        String normalized = modelUrl.trim();
        if (normalized.isEmpty()) return normalized;
        String baseUrl = normalized.replaceAll("/+$", "");
        if (baseUrl.endsWith(CHAT_COMPLETIONS_SUFFIX)) return baseUrl;
        if (baseUrl.equals(MINI_MAX_GLOBAL_BASE_URL)
                || baseUrl.equals(MINI_MAX_CHINA_BASE_URL)
                || baseUrl.contains("xiaomimimo.com")) {
            return baseUrl + CHAT_COMPLETIONS_SUFFIX;
        }
        return normalized;
    }

    // ========== 核心：从wxapkg页面接收API数据 ==========
    public void addApis(List<String[]> apiDataList) {
        SwingUtilities.invokeLater(() -> {
            int added = 0;
            for (String[] apiData : apiDataList) {
                String apiPath = apiData[0];
                String sourceFile = apiData.length > 1 ? apiData[1] : "";
                String context = apiData.length > 2 ? apiData[2] : "";
                if (addApiInternal(apiPath, sourceFile, context)) {
                    added++;
                }
            }
            if (added > 0) {
                updateStatus();
                // 如果已输入域名则自动刷新
                if (!getCurrentDomain().isEmpty()) {
                    refreshHistoryCount();
                }
            }
        });
    }

    private boolean addApiInternal(String apiPath, String sourceFile, String context) {
        for (ApiEntry entry : apiEntries) {
            if (entry.apiPath.equals(apiPath)) return false;
        }
        // 域名由用户手动输入，不再自动提取
        ApiEntry entry = new ApiEntry(idCounter.incrementAndGet(), apiPath, sourceFile, context, "", 0);
        apiEntries.add(entry);
        apiListModel.addRow(new Object[]{entry.id, entry.apiPath, entry.sourceFile, 0});
        return true;
    }

    // ========== 域名提取 ==========
    public static String extractDomain(String apiPath) {
        if (apiPath == null || apiPath.trim().isEmpty()) return "";
        String url = apiPath.trim();
        if (url.startsWith("https://")) url = url.substring(8);
        else if (url.startsWith("http://")) url = url.substring(7);
        else if (url.startsWith("//")) url = url.substring(2);
        if (url.startsWith("/") || url.startsWith("./") || url.startsWith("../")) return "";

        int slashIdx = url.indexOf('/');
        String domainPart = slashIdx > 0 ? url.substring(0, slashIdx) : url;
        int colonIdx = domainPart.lastIndexOf(':');
        if (colonIdx > 0 && colonIdx < domainPart.length() - 1) {
            try { parseInt(domainPart.substring(colonIdx + 1)); domainPart = domainPart.substring(0, colonIdx); }
            catch (NumberFormatException ignored) {}
        }
        int atIdx = domainPart.lastIndexOf('@');
        if (atIdx > 0) domainPart = domainPart.substring(atIdx + 1);
        return domainPart.toLowerCase();
    }

    // ========== Burp历史流量拉取 ==========
    private String getCurrentDomain() {
        return domainField.getText().trim().toLowerCase();
    }

    // ========== AI配置持久化 ==========
    private void loadAiConfig() {
        try {
            Config.SavedConfig cfg = Config.loadAiConfig();
            if (cfg.getAiApiKey() != null) apiKeyField.setText(cfg.getAiApiKey());
            if (cfg.getAiModelUrl() != null) modelUrlField.setText(cfg.getAiModelUrl());
            if (cfg.getAiModelName() != null) modelNameField.setText(cfg.getAiModelName());
            if (cfg.getAiTimeout() != null) timeoutField.setText(cfg.getAiTimeout());
            if (cfg.getAiContextLength() != null) contextLengthField.setText(cfg.getAiContextLength());
            if (cfg.getAiExtraHeaders() != null) extraHeadersField.setText(cfg.getAiExtraHeaders());
            if (cfg.getAiPromptTemplate() != null) promptArea.setText(cfg.getAiPromptTemplate());
            if (cfg.getAiDomain() != null) domainField.setText(cfg.getAiDomain());
            syncPresetSelection();
        } catch (Exception ignored) {}
    }

    private void saveCurrentAiConfigSilently() {
        Config.saveAiConfig(
            apiKeyField.getText().trim(),
            modelUrlField.getText().trim(),
            modelNameField.getText().trim(),
            timeoutField.getText().trim(),
            contextLengthField.getText().trim(),
            extraHeadersField.getText().trim(),
            promptArea.getText(),
            domainField.getText().trim().toLowerCase()
        );
    }

    private List<ProxyHttpRequestResponse> getCachedHistory() {
        if (cachedHistory == null) {
            try { cachedHistory = montoyaApi.proxy().history(); }
            catch (Exception e) { cachedHistory = new ArrayList<>(); }
        }
        return cachedHistory;
    }

    private List<ProxyHttpRequestResponse> getDomainHistory(String domain) {
        if (domain == null || domain.isEmpty()) return new ArrayList<>();
        if (domainHistoryCache.containsKey(domain)) return domainHistoryCache.get(domain);

        List<ProxyHttpRequestResponse> result = new ArrayList<>();
        // 获取所有流量
//        List<HttpRequestResponse> test = montoyaApi.siteMap().requestResponses();
//        for (HttpRequestResponse reqresp : test) {
//            montoyaApi.logging().logToOutput(reqresp);
//        }

        for (ProxyHttpRequestResponse entry : getCachedHistory()) {
            try {
                // 过滤掉扩展自己发出的请求（带 AIJaySenWxapkg 标记头的）
                if (entry.request().hasHeader("AIJaySenWxapkg")) continue;
                String reqDomain = extractDomain(entry.request().url());
                if (domain.equals(reqDomain)) result.add(entry);
            } catch (Exception ignored) {}
        }
        domainHistoryCache.put(domain, result);
        return result;
    }

    private void refreshHistoryCount() {
//        montoyaApi.logging().logToOutput("[DEBUG] refreshHistoryCount() 进入");
        String domain = getCurrentDomain();
        if (domain.isEmpty()) {
            JOptionPane.showMessageDialog(null, "请先输入目标域名！", "提示", JOptionPane.WARNING_MESSAGE);
            return;
        }
        statusLabel.setText("正在拉取 " + domain + " 的历史请求...");
        new SwingWorker<Integer, Void>() {
            @Override
            protected Integer doInBackground() {
                cachedHistory = null;
                domainHistoryCache.clear();
                List<ProxyHttpRequestResponse> matched = getDomainHistory(domain);
                return matched.size();
            }
            @Override
            protected void done() {
                try {
                    int count = get();
                    for (ApiEntry entry : apiEntries) entry.historyCount = count;
                    apiListModel.setRowCount(0);
                    for (ApiEntry entry : apiEntries) {
                        apiListModel.addRow(new Object[]{entry.id, entry.apiPath, entry.sourceFile, entry.historyCount});
                    }
                    updateStatus();
                    loadHistoryDetailForDomain();
                } catch (Exception e) {
                    updateStatus();
                }
            }
        }.execute();
    }

    // ========== 域名输入后加载历史 ==========
    private void loadHistoryForDomain() {
        String domain = getCurrentDomain();
        if (domain.isEmpty()) {
            JOptionPane.showMessageDialog(null, "请先输入目标域名！", "提示", JOptionPane.WARNING_MESSAGE);
            return;
        }
        refreshHistoryCount();
    }

    private void loadHistoryDetailForDomain() {
//        montoyaApi.logging().logToOutput("[DEBUG] loadHistoryDetailForDomain() 进入");
        String domain = getCurrentDomain();
        if (domain.isEmpty()) {
            historyDetailArea.setText("（请输入域名后点击\"应用\"）");
            return;
        }
        historyDetailArea.setText("正在加载 " + domain + " 的历史请求数据...");
        new SwingWorker<String, Void>() {
            @Override
            protected String doInBackground() {
                List<ProxyHttpRequestResponse> matched = getDomainHistory(domain);
                StringBuilder sb = new StringBuilder();
                sb.append("域名: ").append(domain).append("\n");
                sb.append("匹配到 ").append(matched.size()).append(" 条历史请求\n");
                sb.append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");

                int limit = Math.min(matched.size(), 50);
                for (int i = 0; i < limit; i++) {
                    ProxyHttpRequestResponse entry = matched.get(i);
                    try {
                        HttpRequest req = entry.request();
                        if (isStaticResource(req.url())) continue; // 跳过静态资源
                        sb.append("---\n");
                        // 请求行
                        sb.append(req.method()).append(" ").append(req.path()).append(" HTTP/1.1\n");
                        // Headers
                        for (HttpHeader h : req.headers()) {
                            sb.append(h.name()).append(": ").append(h.value()).append("\n");
                        }
                        sb.append("\n");
                        // Body
                        if (req.body() != null && req.body().length() > 0) {
                            String body = req.bodyToString();
                            int maxLen = Math.min(body.length(), 1000);
                            sb.append(body.substring(0, maxLen));
                            if (body.length() > maxLen) sb.append("\n...(已截断)");
                            sb.append("\n");
                        }
                        sb.append("\n");
                    } catch (Exception ex) {
                        sb.append("【").append(i + 1).append("】解析失败: ").append(ex.getMessage()).append("\n\n");
                    }
                }
                if (matched.size() > limit) {
                    sb.append("... 还有 ").append(matched.size() - limit).append(" 条未展示\n");
                }
                return sb.toString();
            }
            @Override
            protected void done() {
                try { historyDetailArea.setText(get()); }
                catch (Exception e) { historyDetailArea.setText("加载失败: " + e.getMessage()); }
            }
        }.execute();
    }

    // ========== 列表操作 ==========
    private void clearApiList() {
        apiEntries.clear();
        apiListModel.setRowCount(0);
        idCounter.set(0);
        historyDetailArea.setText("");
        domainHistoryCache.clear();
        cachedHistory = null;
        updateStatus();
    }

    private void deleteSelectedApis() {
        int[] rows = apiListTable.getSelectedRows();
        if (rows == null || rows.length == 0) {
            JOptionPane.showMessageDialog(null, "请先选择要删除的接口！", "提示", JOptionPane.WARNING_MESSAGE);
            return;
        }
        // 从后往前删除，避免索引偏移
        for (int i = rows.length - 1; i >= 0; i--) {
            int row = rows[i];
            if (row >= 0 && row < apiEntries.size()) {
                apiEntries.remove(row);
                apiListModel.removeRow(row);
            }
        }
        historyDetailArea.setText("");
        updateStatus();
    }

    private void addManualApi() {
        JTextField pathField = new JTextField(30);
        pathField.setFont(CN_FONT);
        JTextField sourceField = new JTextField(20);
        sourceField.setFont(CN_FONT);
        sourceField.setText("手动添加");

        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.gridx = 0; gbc.gridy = 0;
        panel.add(new JLabel("API路径:"), gbc);
        gbc.gridx = 1;
        panel.add(pathField, gbc);
        gbc.gridx = 0; gbc.gridy = 1;
        panel.add(new JLabel("来源文件:"), gbc);
        gbc.gridx = 1;
        panel.add(sourceField, gbc);

        int result = JOptionPane.showConfirmDialog(null, panel, "手动新增接口",
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        if (result != JOptionPane.OK_OPTION) return;

        String apiPath = pathField.getText().trim();
        if (apiPath.isEmpty()) {
            JOptionPane.showMessageDialog(null, "API路径不能为空！", "提示", JOptionPane.WARNING_MESSAGE);
            return;
        }
        String sourceFile = sourceField.getText().trim();
        if (sourceFile.isEmpty()) sourceFile = "手动添加";
        if (addApiInternal(apiPath, sourceFile, "")) {
            updateStatus();
            if (!getCurrentDomain().isEmpty()) refreshHistoryCount();
        } else {
            JOptionPane.showMessageDialog(null, "该API路径已存在！", "提示", JOptionPane.WARNING_MESSAGE);
        }
    }

    private void updateStatus() {
        int count = apiEntries.size();
        int totalHistory = apiEntries.stream().mapToInt(e -> e.historyCount).sum();
        statusLabel.setText("就绪，共 " + count + " 条接口，域名匹配 " + totalHistory + " 条历史请求");
    }

    // ========== AI发送逻辑 ==========
    // ========== 测试AI连接 ==========
    private void testAiConnection() {
        saveCurrentAiConfigSilently();
        String apiKey = apiKeyField.getText().trim();
        String modelUrl = modelUrlField.getText().trim();
        if (apiKey.isEmpty() || modelUrl.isEmpty()) {
            JOptionPane.showMessageDialog(null, "请先填写 API Key 和 API 地址！", "提示", JOptionPane.WARNING_MESSAGE);
            return;
        }
        resultArea.setText("正在测试AI连接...");
        new SwingWorker<String, Void>() {
            @Override
            protected String doInBackground() throws Exception {
                String modelName = modelNameField.getText().trim();
                int timeout = parseInt(timeoutField.getText(), 15);
                Map<String, String> extraHeaders = parseExtraHeaders(extraHeadersField.getText());
                return callAiApi(apiKey, modelUrl, modelName, "你好，请回复'连接成功'", timeout, extraHeaders);
            }
            @Override
            protected void done() {
                try {
                    String result = get();
                    resultArea.setText("AI连接测试成功！\n返回内容：\n" + result);
                    appendLog("=== 连接测试 ===\n时间: " + LocalDateTime.now().format(DateTimeFormatter.ofPattern(LOG_DATE_FORMAT))
                            + "\n模型: " + modelUrlField.getText().trim()
                            + "\n结果: 成功\n\n");
                } catch (Exception ex) {
                    resultArea.setText("连接测试失败: " + ex.getMessage());
                    appendLog("=== 连接测试 ===\n时间: " + LocalDateTime.now().format(DateTimeFormatter.ofPattern(LOG_DATE_FORMAT))
                            + "\n模型: " + modelUrlField.getText().trim()
                            + "\n结果: 失败 - " + ex.getMessage() + "\n\n");
                }
            }
        }.execute();
    }

    private void sendSelectedToAI() {
        int[] rows = apiListTable.getSelectedRows();
        if (rows == null || rows.length == 0) {
            JOptionPane.showMessageDialog(null, "请先选择接口！（可Shift多选）"); return;
        }
        saveCurrentAiConfigSilently();
        List<ApiEntry> selected = new ArrayList<>();
        for (int row : rows) {
            if (row >= 0 && row < apiEntries.size()) {
                selected.add(apiEntries.get(row));
            }
        }
        if (selected.isEmpty()) return;
        sendApisToAI(selected);
    }

    private void sendApisToAI(List<ApiEntry> entries) {
//        montoyaApi.logging().logToOutput("[DEBUG] sendApisToAI() 进入, entries=" + entries.size());
        String apiKey = apiKeyField.getText().trim();
        String modelUrl = modelUrlField.getText().trim();
        if (apiKey.isEmpty()) { JOptionPane.showMessageDialog(null, "请配置API Key！"); return; }
        if (modelUrl.isEmpty()) { JOptionPane.showMessageDialog(null, "请配置API地址！"); return; }

        String modelName = modelNameField.getText().trim();
        if (modelName.isEmpty()) modelName = DEFAULT_MODEL_NAME;

        String domain = getCurrentDomain();

        // 1. 构建待分析的API列表（使用解包时预提取的源码上下文）
        StringBuilder apiListStr = new StringBuilder();
        for (int i = 0; i < entries.size(); i++) {
            ApiEntry e = entries.get(i);
            apiListStr.append(i + 1).append(". ").append(e.apiPath);
            if (e.context != null && !e.context.isEmpty()) {
                apiListStr.append("\n   源码上下文:\n").append(e.context);
            }
            apiListStr.append("\n");
        }

        // 2. 构建已观测接口示例：去重 + 精简Headers + 最多25条
        StringBuilder paramRefs = new StringBuilder();
        List<String[]> allReqs = new ArrayList<>(); // 用于前缀检测
        if (!domain.isEmpty()) {
            List<ProxyHttpRequestResponse> history = getDomainHistory(domain);

            // 收集所有非静态请求，按 method+path 去重
            Set<String> seenKeys = new HashSet<>();
            boolean gotFullGet = false, gotFullPost = false;

            for (ProxyHttpRequestResponse entry : history) {
                try {
                    HttpRequest req = entry.request();
                    if (isStaticResource(req.url())) continue;

                    String method = req.method();
                    String path = req.path();
                    String dedupKey = method + " " + path;
                    if (!seenKeys.add(dedupKey)) continue; // 去重

                    // 压缩格式
                    StringBuilder compress = new StringBuilder();
                    compress.append(method).append(" ").append(path);
                    String fullUrl = req.url();
                    String query = fullUrl.contains("?") ? fullUrl.substring(fullUrl.indexOf('?') + 1) : null;
                    if (query != null && !query.isEmpty()) {
                        if (query.length() > 200) query = query.substring(0, 200) + "...";
                        compress.append("?").append(query);
                    }
                    String bodyStr = "";
                    if (req.body() != null && req.body().length() > 0) {
                        bodyStr = req.bodyToString();
                        if (bodyStr != null && !bodyStr.isEmpty()) {
                            if (bodyStr.length() > 200) bodyStr = bodyStr.substring(0, 200) + "...";
                            compress.append("  body:").append(bodyStr);
                        }
                    }

                    // 完整请求（仅保留关键Headers）
                    StringBuilder fullReq = new StringBuilder();
                    fullReq.append(method).append(" ").append(path).append(" HTTP/1.1\n");
                    for (HttpHeader h : req.headers()) {
                        String name = h.name().toLowerCase();
                        if (name.equals("host") || name.equals("authorization")
                                || name.equals("content-type") || name.equals("cookie")
                                || name.equals("referer") || name.equals("x-requested-with")
                                || name.startsWith("x-")) {
                            fullReq.append(h.name()).append(": ").append(h.value()).append("\n");
                        }
                    }
                    fullReq.append("\n");
                    if (!bodyStr.isEmpty()) fullReq.append(bodyStr).append("\n");

                    allReqs.add(new String[]{method, path, compress.toString(), fullReq.toString()});
                } catch (Exception ignored) {}
            }

            // 限制最多25条参考请求
            List<String[]> limitedReqs = allReqs.size() > 25 ? allReqs.subList(0, 25) : allReqs;

            if (!limitedReqs.isEmpty()) {
                paramRefs.append("该域名下共发现 ").append(history.size()).append(" 条请求，去重后 ").append(allReqs.size()).append(" 个接口。\n\n");

                // 完整请求（GET + POST 各一个）
                for (String[] r : limitedReqs) {
                    if (!gotFullGet && "GET".equalsIgnoreCase(r[0])) {
                        paramRefs.append("【完整GET请求示例】\n").append(r[3]).append("\n");
                        gotFullGet = true;
                    }
                    if (!gotFullPost && "POST".equalsIgnoreCase(r[0])) {
                        paramRefs.append("【完整POST请求示例】\n").append(r[3]).append("\n");
                        gotFullPost = true;
                    }
                }

                // 其余压缩展示
                paramRefs.append("【其他已观测接口（压缩格式）】\n");
                for (String[] r : limitedReqs) {
                    paramRefs.append(r[2]).append("\n");
                }
            } else {
                paramRefs = new StringBuilder("未匹配到该域名下的历史请求。");
            }
        } else {
            paramRefs = new StringBuilder("（未设置目标域名，无法提供请求参考。）");
        }

        // 3. 自动检测URL前缀不一致，生成修正指令
        String prefixCorrection = detectPrefixMismatch(allReqs, entries);

        String promptContent = promptArea.getText();
        promptContent = promptContent.replace("{param_refs}", paramRefs.toString());
        promptContent = promptContent.replace("{api_list}", apiListStr.toString().trim());
        String finalPrompt = prefixCorrection + promptContent;

        int ctxLen;
        try { ctxLen = parseInt(contextLengthField.getText().trim()); }
        catch (NumberFormatException ex) { ctxLen = 4096; }

        if (finalPrompt.length() > ctxLen)
            finalPrompt = finalPrompt.substring(0, ctxLen) + "\n...(已截断)";

        int timeout;
        try { timeout = parseInt(timeoutField.getText().trim()); }
        catch (NumberFormatException ex) { timeout = 60; }

        // 解析额外headers
        Map<String, String> extraHeaders = parseExtraHeaders(extraHeadersField.getText().trim());

        resultArea.setText("正在调用AI接口...");
        appendLog("=== 发送请求 ===\n时间: " + LocalDateTime.now().format(DateTimeFormatter.ofPattern(LOG_DATE_FORMAT))
                + "\n模型: " + modelName + "\n地址: " + modelUrl
                + "\nPrompt: " + finalPrompt + "\n");

        String finalPrompt1 = finalPrompt;
        int finalTimeout = timeout;
        String finalModelName = modelName;

        new SwingWorker<String, Void>() {
            @Override
            protected String doInBackground() {
                return callAiApi(apiKey, modelUrl, finalModelName, finalPrompt1, finalTimeout, extraHeaders);
            }
            @Override
            protected void done() {
                try {
                    // montoyaApi.logging().logToOutput("[DEBUG] done() 开始 get()...");
                    String result = get();
                    // montoyaApi.logging().logToOutput("[DEBUG] done() get() 完成, result长度=" + (result != null ? result.length() : 0));
                    String display = (result != null && !result.isEmpty()) ? result : "AI返回为空";
                    // montoyaApi.logging().logToOutput("[DEBUG] done() 开始 setText, display长度=" + display.length());
                    resultArea.setText(display);
                    // montoyaApi.logging().logToOutput("[DEBUG] done() setText 完成, 开始 appendLog");
                    appendLog("--- 返回结果 ---\n" + display + "\n\n");
                    // montoyaApi.logging().logToOutput("[DEBUG] done() 完成");
                    // 自动解析并执行AI生成的HTTP请求
                    executeAiGeneratedRequests(display);
                } catch (Exception ex) {
                    StringWriter sw = new StringWriter();
                    ex.printStackTrace(new PrintWriter(sw));
                    // montoyaApi.logging().logToOutput("[DEBUG] done() 异常: " + ex + "\n" + sw);
                    String errMsg = "调用失败: " + ex.getMessage();
                    resultArea.setText(errMsg);
                    appendLog(errMsg + "\n\n");
                }
            }
        }.execute();
    }

    // ========== 自动执行AI生成的HTTP请求 ==========
    private void executeAiGeneratedRequests(String aiResponse) {
        List<String> requests = extractHttpRequests(aiResponse);
        if (requests.isEmpty()) {
            historyDetailArea.setText("（AI返回中未找到可执行的HTTP请求块）");
            return;
        }
        historyDetailArea.setText("正在通过Burp发送 " + requests.size() + " 个AI生成的请求...");
        new SwingWorker<String, Void>() {
            @Override
            protected String doInBackground() {
                StringBuilder result = new StringBuilder();
                result.append("=== 自动执行AI生成的HTTP请求（通过Burp引擎） ===\n\n");
                for (int i = 0; i < requests.size(); i++) {
                    String raw = requests.get(i);
                    try {
                        // 统一换行符
                        raw = raw.replace("\r\n", "\n").replace("\r", "\n");
                        String[] lines = raw.split("\n");
                        if (lines.length == 0) continue;

                        // 解析请求行
                        String requestLine = lines[0].trim();
                        String[] parts = requestLine.split(" ", 3);
                        if (parts.length < 2) continue;
                        String method = parts[0].toUpperCase();
                        String path = parts[1];

                        // 解析Headers和Body
                        String host = null;
                        java.util.List<String> headerLines = new java.util.ArrayList<>();
                        int bodyStart = -1;
                        for (int j = 1; j < lines.length; j++) {
                            String line = lines[j];
                            // 去除行尾\r
                            if (line.endsWith("\r")) line = line.substring(0, line.length() - 1);
                            if (line.isEmpty()) {
                                bodyStart = j + 1;
                                break;
                            }
                            int colonIdx = line.indexOf(':');
                            if (colonIdx > 0) {
                                String key = line.substring(0, colonIdx).trim();
                                String val = line.substring(colonIdx + 1).trim();
                                if ("Host".equalsIgnoreCase(key)) host = val;
                                headerLines.add(key + ": " + val);
                            }
                        }

                        if (host == null || host.isEmpty()) {
                            result.append("请求 ").append(i + 1).append(" 跳过: 缺少Host头\n\n");
                            continue;
                        }

                        // 清理Host，提取端口和协议
                        String cleanHost = host;
                        int hostColon = cleanHost.indexOf(':');
                        if (hostColon > 0) cleanHost = cleanHost.substring(0, hostColon);
                        int port;
                        boolean isHttps;
                        if (hostColon > 0) {
                            port = Integer.parseInt(host.substring(hostColon + 1));
                            // 非443/80端口也从历史确认协议类型
                            isHttps = detectScheme(cleanHost);
                        } else {
                            // AI没带端口号，从历史请求中探测真实端口和协议
                            int[] schemePort = detectSchemeAndPort(cleanHost);
                            isHttps = (schemePort[0] == 1);
                            port = schemePort[1];
                        }

                        // 提取Body
                        String bodyStr = "";
                        if (bodyStart > 0 && bodyStart < lines.length) {
                            StringBuilder sb = new StringBuilder();
                            for (int j = bodyStart; j < lines.length; j++) {
                                if (j > bodyStart) sb.append("\n");
                                sb.append(lines[j]);
                            }
                            bodyStr = sb.toString().trim();
                        }

                        // 通过Burp引擎发送：从URL构建请求，避免HttpRequest.httpRequest(service, raw)的内部解析问题
                        String scheme = isHttps ? "https" : "http";
                        String fullUrl = scheme + "://" + cleanHost + ":" + port + path;
                        HttpService service = HttpService.httpService(cleanHost, port, isHttps);

                        HttpRequest montoyaReq = HttpRequest.httpRequestFromUrl(fullUrl)
                                .withService(service)
                                .withMethod(method);

                        // 设置Body
                        if (!bodyStr.isEmpty()) {
                            montoyaReq = montoyaReq.withBody(bodyStr);
                        }

                        // 添加非Host类Headers
                        for (String hl : headerLines) {
                            int ci = hl.indexOf(':');
                            if (ci > 0) {
                                String hName = hl.substring(0, ci).trim();
                                String hVal = hl.substring(ci + 1).trim();
                                if (!"Host".equalsIgnoreCase(hName) && !hName.isEmpty() && !hVal.isEmpty()) {
                                    try {
                                        montoyaReq = montoyaReq.withHeader(HttpHeader.httpHeader(hName, hVal));
                                    } catch (Exception ignored) {
                                        // 跳过无法设置的header
                                    }
                                }
                            }
                        }

                        result.append("--- 请求 ").append(i + 1).append(" ---\n");
                        result.append(method).append(" https://").append(cleanHost).append(path).append("\n");

                        HttpRequestResponse attackReqResp = montoyaApi.http().sendRequest(montoyaReq.withHeader(HttpHeader.httpHeader("AIJaySenWxapkg", "true")));
                        result.append("响应状态: ").append(attackReqResp.response().statusCode()).append("\n");
                        String respBody = attackReqResp.response().bodyToString();
                        if (respBody != null && !respBody.isEmpty()) {
                            if (respBody.length() > 3000) respBody = respBody.substring(0, 3000) + "\n...(已截断)";
                            result.append(respBody).append("\n");
                        }
                        result.append("\n");
                    } catch (Exception e) {
                        result.append("请求 ").append(i + 1).append(" 执行失败: ").append(e.getMessage()).append("\n\n");
                    }
                }
                return result.toString();
            }
            @Override
            protected void done() {
                try { historyDetailArea.setText(get()); }
                catch (Exception e) { historyDetailArea.setText("执行失败: " + e.getMessage()); }
            }
        }.execute();
    }

    private static List<String> extractHttpRequests(String text) {
        List<String> requests = new ArrayList<>();
        // 方式1：查找 ``` 包裹的 HTTP 请求块
        int pos = 0;
        while (true) {
            int start = text.indexOf("```", pos);
            if (start < 0) break;
            int contentStart = text.indexOf('\n', start + 3);
            if (contentStart < 0) break;
            int end = text.indexOf("```", contentStart);
            if (end < 0) break;
            String block = text.substring(contentStart + 1, end).trim();
            if (block.length() > 10 && (block.startsWith("GET ") || block.startsWith("POST ")
                    || block.startsWith("PUT ") || block.startsWith("DELETE ")
                    || block.startsWith("PATCH "))) {
                requests.add(block);
            }
            pos = end + 3;
        }
        if (!requests.isEmpty()) return requests;

        // 方式2：兜底解析 — 查找缩进的完整请求示例块
        // AI 输出格式: "    POST /path HTTP/1.1\n    Host: xxx\n    ...\n    \n    {body}"
        String[] lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n");
        int i = 0;
        while (i < lines.length) {
            String line = lines[i];
            // 检测以4空格缩进开头的HTTP请求行
            if (line.startsWith("    ") && line.length() > 14) {
                String rest = line.substring(4).trim();
                if (rest.startsWith("GET ") || rest.startsWith("POST ") || rest.startsWith("PUT ")
                        || rest.startsWith("DELETE ") || rest.startsWith("PATCH ")) {
                    StringBuilder block = new StringBuilder();
                    block.append(rest).append("\n");
                    int j = i + 1;
                    // 收集后续缩进行直到非缩进行或下一个接口路径标记
                    while (j < lines.length) {
                        String next = lines[j];
                        if (next.startsWith("    ") && next.length() > 4) {
                            block.append(next.substring(4)).append("\n");
                        } else if (next.trim().startsWith("【") || next.trim().startsWith("完整请求示例")) {
                            break; // 下一个接口标记
                        } else if (next.trim().isEmpty()) {
                            // 空行可能是请求体的分隔
                            if (j + 1 < lines.length && lines[j + 1].startsWith("    ")) {
                                block.append("\n");
                            } else {
                                break;
                            }
                        } else {
                            break;
                        }
                        j++;
                    }
                    String b = block.toString().trim();
                    if (b.length() > 10) {
                        requests.add(b);
                    }
                    i = j;
                    continue;
                }
            }
            i++;
        }
        return requests;
    }

    /**
     * 调用AI API（兼容OpenAI / 通义千问 / DeepSeek / 本地大模型等）
     */
    private String callAiApi(String apiKey, String modelUrl, String modelName,
                             String userPrompt, int timeoutSec,
                             Map<String, String> extraHeaders) {
        // montoyaApi.logging().logToOutput("[DEBUG] callAiApi 进入, prompt=" + userPrompt.length() + "chars");
        OkHttpClient client = new OkHttpClient.Builder()
                .connectTimeout(timeoutSec, TimeUnit.SECONDS)
                .readTimeout(timeoutSec, TimeUnit.SECONDS)
                .writeTimeout(timeoutSec, TimeUnit.SECONDS)
                .build();
        // montoyaApi.logging().logToOutput("[DEBUG] OkHttpClient 创建完成");

        // 构建messages（OpenAI Chat格式）
        // montoyaApi.logging().logToOutput("[DEBUG] 开始 escapeJson...");
        String escaped = escapeJson(userPrompt);
        // montoyaApi.logging().logToOutput("[DEBUG] escapeJson 完成, escaped=" + escaped.length() + "chars");
        String messagesJson = "[{\"role\":\"user\",\"content\":" + escaped + "}]";
        // montoyaApi.logging().logToOutput("[DEBUG] messagesJson 构建完成, len=" + messagesJson.length());

        // montoyaApi.logging().logToOutput("[DEBUG] 开始 String.format...");
        String jsonBody = String.format(
                "{\"model\":\"%s\",\"messages\":%s,\"temperature\":0.1}",
                escapeJsonPlain(modelName), messagesJson
        );
        // montoyaApi.logging().logToOutput("[DEBUG] jsonBody 完成, len=" + jsonBody.length());

        // montoyaApi.logging().logToOutput("[DEBUG] 开始 RequestBody.create...");
        RequestBody body = RequestBody.create(jsonBody, MediaType.parse("application/json;charset=utf-8"));
        // montoyaApi.logging().logToOutput("[DEBUG] RequestBody 完成");

        // 特殊处理：Mimo API 使用 api-key 头
        boolean isMimo = modelUrl.contains("xiaomimimo.com");
        String apiUrl = normalizeChatCompletionsUrl(modelUrl);
        String authHeaderName = "Authorization";
        String authHeaderValue = "Bearer " + apiKey;
        if (isMimo) {
            authHeaderName = "api-key";
            authHeaderValue = apiKey;
        }

        Request.Builder reqBuilder = new Request.Builder()
                .url(apiUrl)
                .post(body)
                .header(authHeaderName, authHeaderValue)
                .header("Content-Type", "application/json");

        // 添加额外自定义headers
        if (extraHeaders != null) {
            for (Map.Entry<String, String> h : extraHeaders.entrySet()) {
                reqBuilder.header(h.getKey(), h.getValue());
            }
        }

        // montoyaApi.logging().logToOutput("[DEBUG] 开始 execute HTTP 请求...");
        try (Response response = client.newCall(reqBuilder.build()).execute()) {
            // montoyaApi.logging().logToOutput("[DEBUG] HTTP 响应返回, code=" + response.code());
            if (!response.isSuccessful()) {
                String errorBody = response.body() != null ? response.body().string() : "";
                return "HTTP " + response.code() + " 错误:\n" + errorBody;
            }
            String responseBody = response.body() != null ? response.body().string() : "";
            // montoyaApi.logging().logToOutput("[DEBUG] response body 读取完成, 长度=" + responseBody.length());
            String extracted = extractContentFromResponse(responseBody);
            // montoyaApi.logging().logToOutput("[DEBUG] extractContent 返回, 长度=" + extracted.length());
            return extracted;
        } catch (IOException e) {
            return "调用异常: " + e.getMessage();
        }
    }

    private Map<String, String> parseExtraHeaders(String headerText) {
        Map<String, String> result = new LinkedHashMap<>();
        if (headerText == null || headerText.isEmpty()) return result;
        String[] pairs = headerText.split(";");
        for (String pair : pairs) {
            int colonIdx = pair.indexOf(':');
            if (colonIdx > 0) {
                String key = pair.substring(0, colonIdx).trim();
                String val = pair.substring(colonIdx + 1).trim();
                if (!key.isEmpty()) result.put(key, val);
            }
        }
        return result;
    }

    private static final ObjectMapper JSON_MAPPER = new ObjectMapper();

    private String extractContentFromResponse(String jsonResponse) {
        try {
            JsonNode root = JSON_MAPPER.readTree(jsonResponse);
            JsonNode choices = root.get("choices");
            if (choices != null && choices.isArray() && choices.size() > 0) {
                JsonNode message = choices.get(0).get("message");
                if (message != null) {
                    JsonNode content = message.get("content");
                    if (content != null) return content.asText();
                }
            }
            // fallback: 返回原始响应
            return jsonResponse;
        } catch (Exception e) {
            return jsonResponse;
        }
    }

    private String escapeJson(String text) {
        // montoyaApi.logging().logToOutput("[DEBUG] escapeJson 进入, text长度=" + text.length());
        return "\"" + escapeJsonPlain(text) + "\"";
    }

    private String escapeJsonPlain(String text) {
        StringBuilder sb = new StringBuilder(text.length() + 50);
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            switch (c) {
                case '\\': sb.append("\\\\"); break;
                case '"':  sb.append("\\\""); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                case '\b': sb.append("\\b"); break;
                case '\f': sb.append("\\f"); break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        return sb.toString();
    }

    private static final Set<String> STATIC_EXTENSIONS = Set.of(
            "js", "css", "png", "jpg", "jpeg", "gif", "svg", "ico", "webp", "bmp",
            "woff", "woff2", "ttf", "eot", "otf",
            "map", "mp4", "mp3", "wav", "ogg", "webm", "avi",
            "pdf", "zip", "gz", "tar", "rar", "7z",
            "json", "txt", "xml", "html", "htm"
    );

    /**
     * 从历史请求中探测目标域名的协议类型
     */
    private boolean detectScheme(String host) {
        int[] result = detectSchemeAndPort(host);
        return result[0] == 1;
    }

    /**
     * 从历史请求中探测目标域名的真实协议和端口
     * @return int[2]: [0]=scheme(1=https,0=http), [1]=port
     */
    private int[] detectSchemeAndPort(String host) {
        String domain = getCurrentDomain();
        if (domain.isEmpty()) return new int[]{1, 443};
        List<ProxyHttpRequestResponse> history = getDomainHistory(domain);
        for (ProxyHttpRequestResponse entry : history) {
            try {
                String url = entry.request().url();
                boolean isHttps = url.startsWith("https");
                // 从URL中提取端口: scheme://host:port/path
                int schemeEnd = url.indexOf("://");
                if (schemeEnd < 0) continue;
                String hostPart = url.substring(schemeEnd + 3);
                int pathStart = hostPart.indexOf('/');
                if (pathStart >= 0) hostPart = hostPart.substring(0, pathStart);
                int portColon = hostPart.lastIndexOf(':');
                if (portColon > 0) {
                    return new int[]{isHttps ? 1 : 0, Integer.parseInt(hostPart.substring(portColon + 1))};
                }
                // 无显式端口，使用协议默认端口
                return new int[]{isHttps ? 1 : 0, isHttps ? 443 : 80};
            } catch (Exception ignored) {}
        }
        return new int[]{1, 443};
    }

    private boolean isStaticResource(String url) {
        if (url == null) return false;
        String lower = url.toLowerCase();
        int qIdx = lower.indexOf('?');
        if (qIdx > 0) lower = lower.substring(0, qIdx);
        int dotIdx = lower.lastIndexOf('.');
        if (dotIdx < 0) return false;
        String ext = lower.substring(dotIdx + 1);
        // 只过滤短扩展名（1~5字符），避免误杀API路径中的点
        return ext.length() <= 5 && STATIC_EXTENSIONS.contains(ext);
    }

    // ========== 源码上下文读取 ==========
    /**
     * 自动检测待推测API是否缺少已观测API的URL前缀，生成明确修正指令
     */
    private String detectPrefixMismatch(List<String[]> observedReqs, List<ApiEntry> pendingApis) {
        if (observedReqs == null || observedReqs.isEmpty()) return "";
        if (pendingApis == null || pendingApis.isEmpty()) return "";

        // 提取所有已观测路径
        List<String> paths = new ArrayList<>();
        for (String[] r : observedReqs) {
            if (r.length > 1 && r[1] != null && !r[1].isEmpty()) {
                paths.add(r[1]); // r[1] is path
            }
        }
        if (paths.size() < 2) return "";

        // 找最长公共前缀（以 / 为分隔）
        String first = paths.get(0);
        String commonPrefix = first;
        for (int i = 1; i < paths.size(); i++) {
            String p = paths.get(i);
            int idx = 0;
            while (idx < commonPrefix.length() && idx < p.length()
                    && commonPrefix.charAt(idx) == p.charAt(idx)) {
                idx++;
            }
            commonPrefix = commonPrefix.substring(0, idx);
        }
        // 截断到最后一个 / 之后（保留目录前缀）
        int lastSlash = commonPrefix.lastIndexOf('/');
        if (lastSlash <= 0) return "";
        commonPrefix = commonPrefix.substring(0, lastSlash + 1); // e.g. "/shop/api/"

        // 检查待推测接口是否缺少前缀
        StringBuilder mismatches = new StringBuilder();
        for (ApiEntry e : pendingApis) {
            String apiPath = e.apiPath;
            if (!apiPath.startsWith("/")) apiPath = "/" + apiPath;
            if (!apiPath.startsWith(commonPrefix)) {
                String corrected = commonPrefix + apiPath.substring(1); // 去掉开头的 /
                mismatches.append("  ").append(apiPath).append("  → 请修正为  ").append(corrected).append("\n");
            }
        }
        if (mismatches.length() == 0) return "";

        return "【路径修正指令】以下接口路径缺少已观测到的通用前缀 " + commonPrefix
                + "，推测和请求时请使用修正后的完整路径：\n" + mismatches + "\n";
    }

    // ========== 日志操作 ==========
    private void appendLog(String msg) {
        try {
            Files.createDirectories(LOG_FILE.getParentFile().toPath());
            Files.writeString(LOG_FILE.toPath(), msg, java.nio.file.StandardOpenOption.CREATE, java.nio.file.StandardOpenOption.APPEND);
        } catch (IOException e) {
            System.err.println("[JaySenWxapkg] 写入日志失败: " + e.getMessage());
        }
    }

    private void openLogDirectory() {
        try {
            Files.createDirectories(LOG_FILE.getParentFile().toPath());
            Desktop.getDesktop().open(LOG_FILE.getParentFile());
        } catch (IOException e) {
            JOptionPane.showMessageDialog(null, "打开目录失败：" + e.getMessage(), "错误", JOptionPane.ERROR_MESSAGE);
        }
    }

    // ========== 数据模型 ==========
    public static class ApiEntry {
        int id;
        String apiPath;
        String sourceFile;
        String context;
        String domain;
        int historyCount;

        public ApiEntry(int id, String apiPath, String sourceFile, String context, String domain, int historyCount) {
            this.id = id;
            this.apiPath = apiPath;
            this.sourceFile = sourceFile;
            this.context = context;
            this.domain = domain;
            this.historyCount = historyCount;
        }
        public String getApiPath() { return apiPath; }
        public String getSourceFile() { return sourceFile; }
        public String getContext() { return context; }
        public String getDomain() { return domain; }
        public int getHistoryCount() { return historyCount; }
    }
}
