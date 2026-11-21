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
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.io.IOException;

/**
 * MCP Server 标签页：
 *  - 端口可修改、启用/关闭（默认启用）
 *  - 给 AI 客户端（Trae / Claude Desktop / Cursor 等）提供小程序反编译能力
 */
public class McpServerTab {
    public static final String DEFAULT_PORT = "62000";
    private static final int MAX_LOG_LINES = 5000;

    private final MontoyaApi montoyaApi;
    private final McpServerCore core;

    private JTextField portField;
    private JButton toggleBtn;
    private JLabel statusLabel;
    private JTextArea logArea;
    private boolean startedByDefault = false; // 启动时是否按默认配置启动过

    public McpServerTab(MontoyaApi montoyaApi) {
        this.montoyaApi = montoyaApi;
        this.core = new McpServerCore(this::appendLog);
    }

    public Component getUiComponent() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15));
        panel.setBackground(Color.WHITE);

        // 标题
        JLabel titleLabel = new JLabel("MCP Server（AI 反编译能力接口）");
        titleLabel.setFont(new Font("Microsoft YaHei", Font.BOLD, 20));
        titleLabel.setForeground(new Color(0, 114, 187));
        titleLabel.setAlignmentX(Component.CENTER_ALIGNMENT);

        JLabel subTitleLabel = new JLabel("为 AI 客户端提供：反编译小程序、读取代码、搜索代码");
        subTitleLabel.setFont(new Font("Microsoft YaHei", Font.PLAIN, 13));
        subTitleLabel.setForeground(Color.GRAY);
        subTitleLabel.setAlignmentX(Component.CENTER_ALIGNMENT);

        // 控制区：端口 + 开关 + 状态
        JPanel controlPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 5));
        controlPanel.setBackground(Color.WHITE);
        controlPanel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(new Color(200, 200, 200)), "服务控制",
                TitledBorder.LEFT, TitledBorder.TOP, new Font("Microsoft YaHei", Font.BOLD, 12)));

        controlPanel.add(new JLabel("端口："));

        Config.SavedConfig savedConfig = Config.loadConfigFile();
        String savedPort = savedConfig.getMcpServerPort() != null && !savedConfig.getMcpServerPort().trim().isEmpty()
                ? savedConfig.getMcpServerPort().trim() : DEFAULT_PORT;
        boolean savedEnabled = savedConfig.getMcpServerEnabled() == null || savedConfig.getMcpServerEnabled();

        portField = new JTextField(savedPort, 6);
        portField.setFont(new Font("Microsoft YaHei", Font.PLAIN, 14));
        controlPanel.add(portField);

        toggleBtn = new JButton();
        toggleBtn.setForeground(Color.WHITE);
        toggleBtn.setBorderPainted(false);
        toggleBtn.setFocusPainted(false);
        toggleBtn.addActionListener(e -> toggleServer());
        controlPanel.add(toggleBtn);

        statusLabel = new JLabel();
        statusLabel.setFont(new Font("Microsoft YaHei", Font.PLAIN, 13));
        controlPanel.add(statusLabel);

        // 连接配置区
        JPanel connectPanel = new JPanel(new BorderLayout(5, 5));
        connectPanel.setBackground(Color.WHITE);
        connectPanel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(new Color(200, 200, 200)), "Claude Code 配置",
                TitledBorder.LEFT, TitledBorder.TOP, new Font("Microsoft YaHei", Font.BOLD, 12)));

        final JTextArea configArea = new JTextArea(8, 40);
        configArea.setEditable(false);
        configArea.setFont(new Font("Microsoft YaHei", Font.PLAIN, 12));
        configArea.setBackground(new Color(245, 245, 245));
        configArea.setText(buildConfigJson(savedPort));
        connectPanel.add(new JScrollPane(configArea), BorderLayout.CENTER);

        // 端口变化时同步刷新配置示例
        portField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            @Override
            public void insertUpdate(javax.swing.event.DocumentEvent e) {
                configArea.setText(buildConfigJson(portField.getText().trim()));
            }

            @Override
            public void removeUpdate(javax.swing.event.DocumentEvent e) {
                configArea.setText(buildConfigJson(portField.getText().trim()));
            }

            @Override
            public void changedUpdate(javax.swing.event.DocumentEvent e) {
                configArea.setText(buildConfigJson(portField.getText().trim()));
            }
        });

        JButton copyBtn = new JButton("复制连接配置");
        copyBtn.setBackground(new Color(0, 114, 187));
        copyBtn.setForeground(Color.WHITE);
        copyBtn.setBorderPainted(false);
        copyBtn.setFocusPainted(false);
        copyBtn.addActionListener(e -> {
            String snippet = buildConfigJson(portField.getText().trim());
            StringSelection selection = new StringSelection(snippet);
            Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
            clipboard.setContents(selection, null);
            appendLog("已复制连接配置");
        });
        connectPanel.add(copyBtn, BorderLayout.EAST);

        // 日志区
        JPanel logPanel = new JPanel(new BorderLayout(5, 5));
        logPanel.setBackground(Color.WHITE);
        logPanel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(new Color(200, 200, 200)), "运行日志",
                TitledBorder.LEFT, TitledBorder.TOP, new Font("Microsoft YaHei", Font.BOLD, 12)));
        logArea = new JTextArea();
        logArea.setEditable(false);
        logArea.setFont(new Font("Microsoft YaHei", Font.PLAIN, 12));
        logArea.setBackground(Color.BLACK);
        logArea.setForeground(new Color(0, 220, 0));
        JScrollPane logScroll = new JScrollPane(logArea);
        logScroll.setPreferredSize(new Dimension(700, 260));
        logPanel.add(logScroll, BorderLayout.CENTER);

        JButton clearLogBtn = new JButton("清空日志");
        clearLogBtn.addActionListener(e -> logArea.setText(""));
        logPanel.add(clearLogBtn, BorderLayout.EAST);

        // 组装
        panel.add(titleLabel);
        panel.add(Box.createVerticalStrut(5));
        panel.add(subTitleLabel);
        panel.add(Box.createVerticalStrut(15));
        panel.add(controlPanel);
        panel.add(Box.createVerticalStrut(10));
        panel.add(connectPanel);
        panel.add(Box.createVerticalStrut(10));
        panel.add(logPanel);

        // 初始化按钮状态 + 默认启动
        applyToggleStyle(false);
        appendLog("JaySenWxapkg MCP Server 初始化完成");
        if (savedEnabled) {
            startedByDefault = true;
            SwingUtilities.invokeLater(this::toggleServer);
        } else {
            appendLog("MCP Server 未启动（上次已关闭，点击按钮启用）");
        }

        return panel;
    }

    /** 生成 Claude Code 的 mcpServers 配置 */
    private static String buildConfigJson(String port) {
        return "{\n"
                + "  \"mcpServers\": {\n"
                + "    \"jaysenwxapkg\": {\n"
                + "      \"url\": \"http://127.0.0.1:" + port + "/sse\"\n"
                + "    }\n"
                + "  }\n"
                + "}";
    }

    /** 停止 MCP 服务（插件卸载/关闭 Burp 时调用，不改变持久化的启用状态） */
    public void shutdown() {
        core.stop();
    }

    /** 切换启用/关闭 */
    private void toggleServer() {
        if (core.isRunning()) {
            core.stop();
            applyToggleStyle(false);
            Config.saveMcpConfig(portField.getText().trim(), false);
        } else {
            String portText = portField.getText().trim();
            int port;
            try {
                port = Integer.parseInt(portText);
                if (port < 1 || port > 65535) throw new NumberFormatException();
            } catch (NumberFormatException e) {
                JOptionPane.showMessageDialog(null, "端口无效，请输入1-65535之间的数字！", "错误", JOptionPane.ERROR_MESSAGE);
                return;
            }
            try {
                core.start(port);
                applyToggleStyle(true);
                Config.saveMcpConfig(portText, true);
            } catch (IOException e) {
                applyToggleStyle(false);
                appendLog("启动失败：" + e.getMessage());
                JOptionPane.showMessageDialog(null, "MCP Server 启动失败：" + e.getMessage(), "错误", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void applyToggleStyle(boolean running) {
        toggleBtn.setText(running ? "关闭服务" : "启用服务");
        toggleBtn.setBackground(running ? new Color(200, 80, 80) : new Color(0, 150, 80));
        statusLabel.setText(running
                ? "运行中 · http://127.0.0.1:" + core.getPort() + "/sse"
                : "已停止");
        statusLabel.setForeground(running ? new Color(0, 140, 0) : Color.GRAY);
    }

    private void appendLog(String msg) {
        SwingUtilities.invokeLater(() -> {
            if (logArea == null) return;
            logArea.append("[" + new java.text.SimpleDateFormat("HH:mm:ss").format(new java.util.Date()) + "] " + msg + "\n");
            // 防止日志无限增长
            if (logArea.getLineCount() > MAX_LOG_LINES) {
                try {
                    int end = logArea.getLineEndOffset(logArea.getLineCount() - MAX_LOG_LINES);
                    logArea.replaceRange("", 0, end);
                } catch (Exception ignored) {}
            }
            logArea.setCaretPosition(logArea.getDocument().getLength());
        });
    }
}
