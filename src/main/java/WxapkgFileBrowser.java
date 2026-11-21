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
import javax.swing.text.*;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeCellRenderer;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreePath;
import java.awt.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.core.JsonProcessingException;

/**
 * 独立文件浏览器窗口（支持搜索高亮+匹配数量+下一个定位，修复相对路径显示，新增高亮左右居中）
 */
public class WxapkgFileBrowser extends JFrame {
    private JTree fileTree;
    private JTextPane contentArea;  // 支持高亮
    private JTextField searchField;
    private JTextField inFileSearchField; // 当前文件内搜索框
    private JList<String> searchResultList;
    private DefaultTreeModel treeModel;
    private File currentRootDir;
    private File currentSelectedFile;
    private boolean loadingFile = false; // 守卫：避免重复触发文件加载
    private String currentKeyword;      // 当前搜索关键词（用于高亮）
    private Path rootPath; // 根目录的标准化Path（计算相对路径）
    private JTextField rootPathField;   // 当前浏览/搜索的根目录

    // 新增：搜索匹配相关变量
    private List<Integer> currentMatchPositions; // 当前文件的所有匹配位置
    private int currentMatchIndex;               // 当前选中的匹配索引
    private JLabel matchCountLabel;              // 显示匹配数量的标签
    private JButton nextMatchBtn;                // 下一个匹配的按钮
    // 新增：上一个按钮
    private JButton prevMatchBtn;
    private MontoyaApi montoyaApi;

    // 构造函数：接收反编译根目录 + MontoyaApi
    public WxapkgFileBrowser(String decompileDir, MontoyaApi montoyaApi) {
        super("wxapkg文件浏览器");
        this.currentRootDir = new File(decompileDir);
        this.currentMatchPositions = new ArrayList<>();
        this.currentMatchIndex = 0;
        this.montoyaApi = montoyaApi;
        initUI();
        loadFileTree(currentRootDir);
        setSize(1200, 800); // 大窗口尺寸
        setLocationRelativeTo(null); // 居中显示
        setDefaultCloseOperation(DISPOSE_ON_CLOSE);
    }

    // 初始化UI（新增TreeCellRenderer控制文件树显示文本）
    private void initUI() {
        // 顶部搜索区（保持不变）
        JPanel searchPanel = new JPanel(new BorderLayout());
        searchPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        searchField = new JTextField();
        setPlaceholder(searchField, "全局搜索文件内容（支持模糊匹配）");
        JButton searchBtn = new JButton("搜索");
        searchBtn.setBackground(new Color(0, 114, 187));
        searchBtn.setForeground(Color.WHITE);
        searchBtn.addActionListener(e -> doGlobalSearch());
        searchPanel.add(new JLabel("全局搜索："), BorderLayout.WEST);
        searchPanel.add(searchField, BorderLayout.CENTER);
        searchPanel.add(searchBtn, BorderLayout.EAST);

        // 顶部：根目录切换 + 搜索区
        JPanel topPanel = new JPanel(new BorderLayout());
        JPanel rootPanel = new JPanel(new BorderLayout(6, 0));
        rootPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 0, 10));
        rootPathField = new JTextField();
        rootPathField.setEditable(false);
        rootPathField.setFont(new Font("Microsoft YaHei", Font.PLAIN, 12));
        JButton switchRootBtn = new JButton("切换目录");
        switchRootBtn.setBackground(new Color(0, 114, 187));
        switchRootBtn.setForeground(Color.WHITE);
        switchRootBtn.setBorderPainted(false);
        switchRootBtn.setFocusPainted(false);
        switchRootBtn.addActionListener(e -> chooseRootDir());
        rootPanel.add(new JLabel("根目录："), BorderLayout.WEST);
        rootPanel.add(rootPathField, BorderLayout.CENTER);
        rootPanel.add(switchRootBtn, BorderLayout.EAST);
        topPanel.add(rootPanel, BorderLayout.NORTH);
        topPanel.add(searchPanel, BorderLayout.SOUTH);

        // 中间内容区（左右分割）
        JSplitPane contentSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        contentSplit.setDividerLocation(280); // 调窄：左边文件树 280px
        contentSplit.setDividerSize(5);

        // 左侧文件树（核心修改：添加自定义渲染器）
        DefaultMutableTreeNode rootNode = new DefaultMutableTreeNode("未选择目录");
        treeModel = new DefaultTreeModel(rootNode);
        fileTree = new JTree(treeModel);
        fileTree.setRootVisible(true);
        fileTree.setShowsRootHandles(true);
        fileTree.setFont(new Font("Microsoft YaHei", Font.PLAIN, 14));

        // 自定义渲染器：显示Entry的key（相对路径），核心修复路径显示
        fileTree.setCellRenderer(new DefaultTreeCellRenderer() {
            @Override
            public Component getTreeCellRendererComponent(JTree tree, Object value, boolean selected, boolean expanded, boolean leaf, int row, boolean hasFocus) {
                super.getTreeCellRendererComponent(tree, value, selected, expanded, leaf, row, hasFocus);
                if (value instanceof DefaultMutableTreeNode) {
                    Object userObj = ((DefaultMutableTreeNode) value).getUserObject();
                    // 如果是Entry对象，显示相对路径（key）
                    if (userObj instanceof Map.Entry) {
                        setText(((Map.Entry<?, ?>) userObj).getKey().toString());
                    }
                }
                return this;
            }
        });

        fileTree.addTreeSelectionListener(e -> {
            // 避免快速切换时多次触发（搜索结果点击会先 setSelectionPath 再手动调用）
            if (loadingFile) return;
            loadSelectedFileContent();
        });
        JScrollPane treeScroll = new JScrollPane(fileTree);
        treeScroll.setBorder(BorderFactory.createTitledBorder("📂 反编译文件结构"));
        contentSplit.setLeftComponent(treeScroll);

        // 右侧：内容预览 + 搜索结果（上下分割）
        JSplitPane rightSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        rightSplit.setDividerLocation(620); // 调大：让文件内容区域更大
        rightSplit.setDividerSize(5);

        // ========== 新增：内容预览区 + 右下角匹配控制区 ==========
        JPanel contentPanel = new JPanel(new BorderLayout());
        contentArea = new JTextPane();
        contentArea.setEditable(false);
        contentArea.setFont(new Font("Microsoft YaHei", Font.PLAIN, 14));
        // 强制JTextPane的文档使用UTF-8编码
        ((AbstractDocument) contentArea.getDocument()).putProperty("charset", StandardCharsets.UTF_8.name());
        contentArea.setEditorKit(new StyledEditorKit() {
            @Override
            public Document createDefaultDocument() {
                Document doc = super.createDefaultDocument();
                doc.putProperty("charset", StandardCharsets.UTF_8.name());
                return doc;
            }
        });
        // 右下角匹配控制区（标签+下一个按钮）
        JPanel matchControlPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        matchCountLabel = new JLabel("匹配数量：0");
        // 新增：上一个按钮
        prevMatchBtn = new JButton("上一个");
        prevMatchBtn.setBackground(new Color(0, 114, 187));
        prevMatchBtn.setForeground(Color.WHITE);
        prevMatchBtn.setEnabled(false); // 初始禁用
        prevMatchBtn.addActionListener(e -> jumpToPrevMatch()); // 绑定事件

        nextMatchBtn = new JButton("下一个");
        nextMatchBtn.setBackground(new Color(0, 114, 187));
        nextMatchBtn.setForeground(Color.WHITE);
        nextMatchBtn.setEnabled(false); // 初始禁用
        nextMatchBtn.addActionListener(e -> jumpToNextMatch()); // 绑定下一个事件
        matchControlPanel.add(prevMatchBtn);
        matchControlPanel.add(matchCountLabel);
        matchControlPanel.add(nextMatchBtn);

        // 组装内容预览区（顶部搜索框+内容+控制区）
        JScrollPane contentScroll = new JScrollPane(contentArea); // 单独定义滚动面板，方便后续获取
        // 新增：当前文件内搜索框
        inFileSearchField = new JTextField();
        setPlaceholder(inFileSearchField, "搜索当前文件内容");
        inFileSearchField.addActionListener(e -> searchInCurrentFile());
        // 新增：输入即搜（DocumentListener）
        inFileSearchField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            public void insertUpdate(javax.swing.event.DocumentEvent e) { searchInCurrentFile(); }
            public void removeUpdate(javax.swing.event.DocumentEvent e) { searchInCurrentFile(); }
            public void changedUpdate(javax.swing.event.DocumentEvent e) { searchInCurrentFile(); }
        });
        JPanel inFileSearchPanel = new JPanel(new BorderLayout());
        inFileSearchPanel.add(new JLabel("🔎 "), BorderLayout.WEST);
        inFileSearchPanel.add(inFileSearchField, BorderLayout.CENTER);
        inFileSearchPanel.setBackground(Color.WHITE);
        // 顶部容器：搜索框 + 内容
        JPanel topContentPanel = new JPanel(new BorderLayout());
        topContentPanel.add(inFileSearchPanel, BorderLayout.NORTH);
        topContentPanel.add(contentScroll, BorderLayout.CENTER);
        topContentPanel.add(matchControlPanel, BorderLayout.SOUTH);
        contentPanel.add(topContentPanel, BorderLayout.CENTER);
        contentPanel.setBorder(BorderFactory.createTitledBorder("📄 文件内容"));
        rightSplit.setTopComponent(contentPanel);

        // 搜索结果区（保持不变）
        searchResultList = new JList<>();
        searchResultList.setFont(new Font("Microsoft YaHei", Font.PLAIN, 14));
        searchResultList.addListSelectionListener(e -> jumpToSearchResult());
        JScrollPane resultScroll = new JScrollPane(searchResultList);
        resultScroll.setBorder(BorderFactory.createTitledBorder("搜索结果"));
        rightSplit.setBottomComponent(resultScroll);

        contentSplit.setRightComponent(rightSplit);

        // 组装窗口
        add(topPanel, BorderLayout.NORTH);
        add(contentSplit, BorderLayout.CENTER);
    }

    /** 选择新的根目录（选择反编译输出根目录即可搜索所有appid的源码） */
    private void chooseRootDir() {
        JFileChooser chooser = new JFileChooser(currentRootDir != null ? currentRootDir : new File("."));
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        chooser.setDialogTitle("选择要浏览/搜索的根目录");
        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            switchRootDir(chooser.getSelectedFile());
        }
    }

    /** 切换根目录并重新加载文件树 */
    private void switchRootDir(File dir) {
        if (dir == null || !dir.isDirectory()) {
            JOptionPane.showMessageDialog(this, "请选择有效目录！", "提示", JOptionPane.WARNING_MESSAGE);
            return;
        }
        this.currentRootDir = dir;
        this.currentSelectedFile = null;
        contentArea.setText("");
        searchResultList.setListData(new String[]{"（请先搜索）"});
        loadFileTree(dir);
    }

    // ===================== 修复：左右居中滚动工具方法（核心） =====================
    /**
     * 将目标位置的文本在JTextPane中左右居中显示（方便查看上下文）
     * @param textPane 目标文本面板
     * @param targetPos 目标字符位置
     */
    private void scrollToCenterHorizontally(JTextPane textPane, int targetPos) {
        try {
            // 1. 获取目标位置对应的视图矩形（匹配文本的边界）
            Rectangle targetRect = textPane.modelToView(targetPos);
            if (targetRect == null) return;

            // 2. 安全获取JViewport（两种方式：推荐方式1，兼容所有场景）
            JViewport viewport = null;
            // 方式1：从JScrollPane中直接获取视口（更稳定，避免父容器层级错误）
            Container parent = textPane.getParent();
            if (parent instanceof JViewport) {
                viewport = (JViewport) parent;
            } else {
                // 方式2：遍历父容器，找到JViewport（兜底方案）
                while (parent != null && !(parent instanceof JViewport)) {
                    parent = parent.getParent();
                }
                if (parent instanceof JViewport) {
                    viewport = (JViewport) parent;
                }
            }

            // 无有效视口，使用默认滚动
            if (viewport == null) {
                textPane.scrollRectToVisible(targetRect);
                return;
            }

            // 3. 获取视口大小和当前滚动位置
            Rectangle viewportRect = viewport.getViewRect();
            Point viewportPos = viewport.getViewPosition();

            // 4. 计算左右居中偏移量：让匹配内容的中心 = 视口的中心
            int targetCenterX = targetRect.x + targetRect.width / 2;
            int viewportCenterX = viewportRect.width / 2;
            int newViewportX = viewportPos.x + (targetCenterX - viewportCenterX);

            // 5. 处理边界情况：避免滚动出文本范围（左不小于0，右不超过文本总宽度）
            int textTotalWidth = textPane.getPreferredSize().width;
            newViewportX = Math.max(0, newViewportX);
            newViewportX = Math.min(newViewportX, textTotalWidth - viewportRect.width);

            // 6. 保持垂直位置不变，只调整水平位置（左右居中），滚动到目标区域
            viewport.setViewPosition(new Point(newViewportX, viewportPos.y));
            textPane.scrollRectToVisible(targetRect);

        } catch (BadLocationException e) {
            // 异常时使用默认滚动逻辑
            textPane.scrollRectToVisible(new Rectangle(targetPos, 0, 10, 20));
            e.printStackTrace();
        }
    }

    // 新增：跳转到上一个匹配（调用修复后的居中滚动方法）
    private void jumpToPrevMatch() {
        if (currentMatchPositions.isEmpty()) return;

        // 索引减1（循环到末尾）
        currentMatchIndex = (currentMatchIndex - 1 + currentMatchPositions.size()) % currentMatchPositions.size();
        int targetPos = currentMatchPositions.get(currentMatchIndex);

        // 定位+滚动（调用修复后的居中方法）
        try {
            contentArea.setCaretPosition(targetPos);
            scrollToCenterHorizontally(contentArea, targetPos);
            // 更新“当前/总数”显示
            updateMatchLabel();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // 新增：更新匹配标签显示（当前/总数）
    private void updateMatchLabel() {
        if (currentMatchPositions.isEmpty()) {
            matchCountLabel.setText("匹配数量：0");
        } else {
            // 显示格式：当前索引+1 / 总数
            matchCountLabel.setText((currentMatchIndex + 1) + "/" + currentMatchPositions.size());
        }
    }

    // 加载文件树（仅修改此方法：跳过上级目录名，直接显示目录内容）
    private void loadFileTree(File rootDir) {
        if (rootDir == null || !rootDir.isDirectory()) {
            JOptionPane.showMessageDialog(this, "无效的反编译目录！", "提示", JOptionPane.WARNING_MESSAGE);
            return;
        }
        if (rootPathField != null) {
            rootPathField.setText(rootDir.getAbsolutePath());
            rootPathField.setCaretPosition(0);
        }
        try {
            this.rootPath = rootDir.toPath().toRealPath();
            // 根节点直接命名为“反编译文件结构”（不再显示上级目录名）
            DefaultMutableTreeNode rootNode = new DefaultMutableTreeNode("反编译文件结构");
            // 直接将传入目录的内容作为根节点的子节点（跳过上级目录名）
            buildTreeNodes(rootNode, rootDir);
            treeModel.setRoot(rootNode);
            // 默认展开根节点（显示其下的内容）
            fileTree.expandPath(new TreePath(rootNode));
        } catch (IOException e) {
            this.rootPath = rootDir.toPath().normalize();
            DefaultMutableTreeNode rootNode = new DefaultMutableTreeNode("反编译文件结构");
            buildTreeNodes(rootNode, rootDir);
            treeModel.setRoot(rootNode);
            fileTree.expandPath(new TreePath(rootNode));
        }
    }

    // 递归构建文件树（核心修改：用Entry包装相对路径+File，不再覆盖userObject）
    private void buildTreeNodes(DefaultMutableTreeNode parentNode, File dir) {
        File[] files = dir.listFiles();
        if (files == null) return;
        for (File file : files) {
            try {
                Path filePath = file.toPath().toRealPath();
                Path relativePath = rootPath.relativize(filePath);

                // 核心修改：Entry的key改为file.getName()（仅显示文件名/目录名）
                // value仍保留File对象，不影响后续读取文件的逻辑
                Map.Entry<String, File> entry = new AbstractMap.SimpleEntry<>(file.getName(), file);
                DefaultMutableTreeNode node = new DefaultMutableTreeNode(entry);
                parentNode.add(node);

                if (file.isDirectory()) {
                    buildTreeNodes(node, file);
                }
            } catch (IOException e) {
                // 异常时同样用file.getName()作为key
                Map.Entry<String, File> entry = new AbstractMap.SimpleEntry<>(file.getName(), file);
                DefaultMutableTreeNode node = new DefaultMutableTreeNode(entry);
                parentNode.add(node);
            }
        }
    }

    // 异步读取文件（修改：强制UTF-8编码 + 异常详细提示，调用修复后的居中滚动）
    private void loadSelectedFileContent() {
        // 守卫：如果上一次加载还未完成，直接返回避免重复
        if (loadingFile) return;
        loadingFile = true;

        // 切换文件时，重置匹配状态
        currentMatchPositions.clear();
        currentMatchIndex = 0;
        matchCountLabel.setText("匹配数量：0");
        prevMatchBtn.setEnabled(false);
        nextMatchBtn.setEnabled(false);

        TreePath selectedPath = fileTree.getSelectionPath();
        if (selectedPath == null) { loadingFile = false; return; }
        DefaultMutableTreeNode selectedNode = (DefaultMutableTreeNode) selectedPath.getLastPathComponent();
        Object userObj = selectedNode.getUserObject();
        if (userObj == null) { loadingFile = false; return; }

        // 核心修改：从Entry中获取File对象
        File selectedFile = null;
        if (userObj instanceof Map.Entry) {
            selectedFile = (File) ((Map.Entry<?, ?>) userObj).getValue();
        }
        currentSelectedFile = selectedFile; // 提升为类字段

        if (selectedFile == null || selectedFile.isDirectory()) {
            contentArea.setText("");
            loadingFile = false;
            return;
        }

        // 超大文件提示（保持不变）
        long fileSize = selectedFile.length();
        if (fileSize > 1024 * 1024 * 5) {
            JOptionPane.showMessageDialog(this, "文件超过5MB，暂不加载（避免卡顿）！", "提示", JOptionPane.WARNING_MESSAGE);
            loadingFile = false;
            return;
        }

        contentArea.setText("Loading...."); // 新增：标注编码

        // 异步读取（强制UTF-8 + 异常捕获）
        File finalSelectedFile = selectedFile;
        final String kw = currentKeyword != null ? currentKeyword : ""; // 后台线程需要的关键字快照（空字符串兜底）
        final String fname = selectedFile != null ? selectedFile.getName().toLowerCase() : ""; // 文件名快照
        new SwingWorker<LoadResult, Void>() {
            @Override
            protected LoadResult doInBackground() throws Exception {
                // 第一步：读文件（按行读取，便于快速预览）
                List<String> lines = new ArrayList<>();
                try (BufferedReader br = new BufferedReader(
                        new InputStreamReader(new FileInputStream(finalSelectedFile), StandardCharsets.UTF_8))) {
                    String line;
                    while ((line = br.readLine()) != null) {
                        lines.add(line);
                    }
                }

                String fileName = finalSelectedFile.getName().toLowerCase();
                boolean isJson = fileName.endsWith(".json");
                boolean isJs = fileName.endsWith(".js");
                boolean isHtml = fileName.endsWith(".html") || fileName.endsWith(".htm") || fileName.endsWith(".wxml");
                boolean isCss = fileName.endsWith(".wxss") || fileName.endsWith(".css");
                // 需要美化：文本型文件即可（大小/超时由 beautifyContent 内部兜底）
                boolean needBeautify = isJson || isJs || isHtml || isCss;
                // 是否二进制：基于内容特征检测
                boolean isBinary = looksLikeBinaryFromLines(lines);
                // 二进制文件直接跳过美化和快速预览
                if (isBinary) needBeautify = false;

                int totalLines = lines.size();
                boolean largeFile = totalLines > 200; // 超过200行启用快速预览
                boolean hasKeyword = kw != null && !kw.isEmpty();
                montoyaApi.logging().logToError("[WxapkgFileBrowser] 加载文件: " + finalSelectedFile.getName() + " | lines=" + totalLines + " | isBinary=" + isBinary + " | needBeautify=" + needBeautify + " | kw=" + kw);
                
                // 第二步：搜索关键字所在行（快速路径）
                List<Integer> matchLineIndices = new ArrayList<>();
                // 关键修复：二进制文件绝不参与行级搜索（避免在混淆/二进制包上扫描几十万行卡死）
                if (hasKeyword && largeFile && !isBinary) {
                    for (int i = 0; i < totalLines; i++) {
                        if (lines.get(i).contains(kw)) matchLineIndices.add(i);
                    }
                }

                String resultContent;
                List<Integer> resultMatches = new ArrayList<>();

                // 关键：决定走哪条路径前，把 kw 保护好
                if (!hasKeyword) {
                    // 无关键词，直接走普通模式
                    StringBuilder csb = new StringBuilder();
                    for (String line : lines) csb.append(line).append("\n");
                    String rc = csb.toString();
                    if (rc.startsWith("\uFEFF")) rc = rc.substring(1);
                    // 二进制文件跳过 beautify，原样返回
                    resultContent = isBinary ? rc : beautifyContent(rc, finalSelectedFile.getName());
                    return new LoadResult(resultContent, resultMatches);
                }

                if (largeFile && hasKeyword && !matchLineIndices.isEmpty() && needBeautify && !isBinary) {
                    // === 快速预览模式：只展示每个匹配前后30行 ===
                    int radius = 30;
                    boolean[] includeMask = new boolean[totalLines];
                    for (int idx : matchLineIndices) {
                        int from = Math.max(0, idx - radius);
                        int to = Math.min(totalLines - 1, idx + radius);
                        for (int i = from; i <= to; i++) includeMask[i] = true;
                    }
                    StringBuilder preview = new StringBuilder();
                    for (int i = 0; i < totalLines; i++) {
                        if (includeMask[i]) preview.append(lines.get(i)).append("\n");
                    }
                    // 对预览做轻量美化
                    String previewContent = preview.toString();
                    if (previewContent.startsWith("\uFEFF")) previewContent = previewContent.substring(1);
                    resultContent = beautifyContent(previewContent, finalSelectedFile.getName());
                    // 计算预览中的关键字位置（快速预览模式已排除二进制）
                    int pos = 0;
                    int maxMatches = 10000; // 兜底：最多匹配1万次
                    while ((pos = resultContent.indexOf(kw, pos)) != -1 && resultMatches.size() < maxMatches) {
                        resultMatches.add(pos);
                        pos += kw.length();
                    }
                } else {
                    // === 普通模式：完整加载+美化 ===
                    StringBuilder contentSb = new StringBuilder();
                    for (String line : lines) contentSb.append(line).append("\n");
                    String rawContent = contentSb.toString();
                    if (rawContent.startsWith("\uFEFF")) rawContent = rawContent.substring(1);
                    // 二进制文件跳过 beautify，原样返回
                    resultContent = isBinary ? rawContent : beautifyContent(rawContent, finalSelectedFile.getName());
                    // 二进制文件也跳过关键字高亮（避免在混淆/二进制包上 indexOf 卡死）
                    if (!isBinary && kw != null && !kw.isEmpty()) {
                        int pos = 0;
                        int maxMatches = 10000; // 兜底：最多匹配1万次，防止短词在巨文件上卡死
                        while ((pos = resultContent.indexOf(kw, pos)) != -1 && resultMatches.size() < maxMatches) {
                            resultMatches.add(pos);
                            pos += kw.length();
                        }
                    }
                }
                return new LoadResult(resultContent, resultMatches);
            }

            @Override
            protected void done() {
                try {
                    // 直接拿到后台已经计算好的美化内容+高亮位置
                    LoadResult result = get();
                    String utf8Content = result.content;
                    // 新增：超大内容截断保护（避免极端情况下 EDT 卡顿）
                    final int MAX_RENDER = 2 * 1024 * 1024; // 2MB
                    if (utf8Content.length() > MAX_RENDER) {
                        utf8Content = utf8Content.substring(0, MAX_RENDER) + "\n\n... [文件过大，仅显示前 " + (MAX_RENDER / 1024 / 1024) + "MB，请用文本编辑器查看完整文件] ...";
                    }
                    StyledDocument doc = contentArea.getStyledDocument();
                    doc.remove(0, doc.getLength());
                    doc.insertString(0, utf8Content, null);

                    // 新增：语法高亮——根据文件类型给关键字/字符串/数字/注释上色
                    applySyntaxHighlight(utf8Content, fname, doc);

                    // 高亮应用（仅设置字符属性，匹配位置已经预计算好）
                    currentMatchPositions.clear();
                    currentMatchPositions.addAll(result.matches);

                    if (kw != null && !kw.isEmpty() && !currentMatchPositions.isEmpty()) {
                        Style highlightStyle = contentArea.addStyle("Highlight", null);
                        StyleConstants.setBackground(highlightStyle, Color.YELLOW);
                        StyleConstants.setForeground(highlightStyle, Color.RED);
                        int keywordLen = kw.length();
                        for (int pos : currentMatchPositions) {
                            doc.setCharacterAttributes(pos, keywordLen, highlightStyle, false);
                        }

                        int matchCount = currentMatchPositions.size();
                        updateMatchLabel();
                        nextMatchBtn.setEnabled(matchCount > 0);

                        if (matchCount > 0) {
                            currentMatchIndex = 0;
                            int firstPos = currentMatchPositions.get(0);
                            contentArea.setCaretPosition(firstPos);
                            // 调用修复后的居中滚动方法
                            scrollToCenterHorizontally(contentArea, firstPos);
                            // 新增：启用上/下按钮
                            prevMatchBtn.setEnabled(true);
                            nextMatchBtn.setEnabled(true);
                        }
                    }
                } catch (Exception e) {
                    contentArea.setText("UTF-8编码读取失败：" + e.getMessage());
                    e.printStackTrace();
                } finally {
                    loadingFile = false; // 无论成功还是失败都释放守卫
                }
            }
        }.execute();
    }

    // 新增：当前文件内搜索
    private void searchInCurrentFile() {
        String keyword = inFileSearchField.getText().trim();
        montoyaApi.logging().logToError("[searchInCurrentFile] 进入 keyword='" + keyword + "' | contentArea.getText().length=" + contentArea.getText().length() + " | firstMatch=" + contentArea.getText().indexOf(keyword));
        // 忽略placeholder文字
        if (keyword.isEmpty() || keyword.equals("搜索当前文件内容")) {
            // 清空搜索：清除高亮
            StyledDocument doc = contentArea.getStyledDocument();
            doc.setCharacterAttributes(0, doc.getLength(), contentArea.getStyle("Normal"), true);
            currentMatchPositions.clear();
            currentMatchIndex = 0;
            matchCountLabel.setText("匹配数量：0");
            prevMatchBtn.setEnabled(false);
            nextMatchBtn.setEnabled(false);
            return;
        }
        // 在当前显示内容中搜索
        String content = contentArea.getText();
        montoyaApi.logging().logToError("[searchInCurrentFile] keyword='" + keyword + "' | contentLen=" + content.length() + " | firstMatch=" + content.indexOf(keyword));
        currentMatchPositions.clear();
        currentMatchIndex = 0;
        int pos = 0;
        int maxMatches = 1000;
        while ((pos = content.indexOf(keyword, pos)) != -1 && currentMatchPositions.size() < maxMatches) {
            currentMatchPositions.add(pos);
            pos += keyword.length();
        }
        // 应用黄色高亮（先清旧样式，再加新样式）
        StyledDocument doc = contentArea.getStyledDocument();
        Style normalStyle = contentArea.getStyle("Normal");
        if (normalStyle != null) doc.setCharacterAttributes(0, doc.getLength(), normalStyle, true);
        Style highlightStyle = contentArea.addStyle("InFileHighlight", null);
        StyleConstants.setBackground(highlightStyle, Color.YELLOW);
        StyleConstants.setForeground(highlightStyle, Color.RED);
        for (int p : currentMatchPositions) {
            doc.setCharacterAttributes(p, keyword.length(), highlightStyle, false);
        }
        matchCountLabel.setText("匹配数量：" + currentMatchPositions.size());
        prevMatchBtn.setEnabled(!currentMatchPositions.isEmpty());
        nextMatchBtn.setEnabled(!currentMatchPositions.isEmpty());
        // 跳转到第一个匹配
        if (!currentMatchPositions.isEmpty()) {
            contentArea.setCaretPosition(currentMatchPositions.get(0));
            scrollToCenterHorizontally(contentArea, currentMatchPositions.get(0));
        }
    }

    // 新增：跳转到下一个匹配（调用修复后的居中滚动方法）
    private void jumpToNextMatch() {
        if (currentMatchPositions.isEmpty()) return;

        // 索引自增（循环到开头）
        currentMatchIndex = (currentMatchIndex + 1) % currentMatchPositions.size();
        int targetPos = currentMatchPositions.get(currentMatchIndex);

        // 定位+滚动到目标位置（调用修复后的居中方法）
        try {
            contentArea.setCaretPosition(targetPos);
            scrollToCenterHorizontally(contentArea, targetPos);
            // 更新“当前/总数”显示
            updateMatchLabel();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // 全局搜索（保持不变）
    private void doGlobalSearch() {
        String keyword = searchField.getText().trim();
        if (keyword.isEmpty() || currentRootDir == null) {
            JOptionPane.showMessageDialog(this, "请输入搜索关键词！", "提示", JOptionPane.WARNING_MESSAGE);
            return;
        }
        // 核心：确保关键词正确赋值
        this.currentKeyword = keyword;

        // 重置匹配状态
        currentMatchPositions.clear();
        currentMatchIndex = 0;
        matchCountLabel.setText("匹配数量：0");
        nextMatchBtn.setEnabled(false);

        new SwingWorker<List<String>, Void>() {
            @Override
            protected List<String> doInBackground() {
                List<String> resultList = new ArrayList<>();
                searchFiles(currentRootDir, keyword, resultList);
                return resultList;
            }

            @Override
            protected void done() {
                try {
                    List<String> results = get();
                    searchResultList.setListData(results.isEmpty() ? new String[]{"未找到匹配内容"} : results.toArray(new String[0]));
                } catch (Exception e) {
                    searchResultList.setListData(new String[]{"搜索失败：" + e.getMessage()});
                }
            }
        }.execute();
    }

    // 递归搜索文件（修改：强制UTF-8编码读取）
    private void searchFiles(File dir, String keyword, List<String> resultList) {
        File[] files = dir.listFiles();
        if (files == null) return;
        for (File file : files) {
            if (file.isDirectory()) {
                searchFiles(file, keyword, resultList);
            } else {
                try {
                    Path filePath = file.toPath().toRealPath();
                    Path relativePath = rootPath.relativize(filePath);
                    // 核心修改：强制UTF-8编码读取文件内容
                    String content = new String(Files.readAllBytes(file.toPath()), StandardCharsets.UTF_8);
                    if (content.contains(keyword)) {
                        resultList.add(relativePath.toString() + " [匹配：" + keyword + "]");
                    }
                } catch (UnsupportedEncodingException e) {
                    // montoyaApi.logging().logToOutput("文件" + file.getName() + "不支持UTF-8编码：" + e.getMessage());
                    continue;
                } catch (Exception e) {
                    continue;
                }
            }
        }
    }

    // 跳转到搜索结果（保持不变，加载文件时自动居中）
    private void jumpToSearchResult() {
        String selectedResult = searchResultList.getSelectedValue();
        if (selectedResult == null || selectedResult.startsWith("未找到") || selectedResult.startsWith("搜索失败")) {
            return;
        }

        String relativePathStr = selectedResult.split(" \\[匹配：")[0];
        Path targetPath = rootPath.resolve(relativePathStr).normalize();
        File targetFile = targetPath.toFile();

        if (!targetFile.exists()) {
            JOptionPane.showMessageDialog(this, "文件不存在！", "提示", JOptionPane.WARNING_MESSAGE);
            return;
        }

        locateFileInTree(targetFile);
        loadSelectedFileContent(); // 加载文件时自动定位第一个匹配并居中
    }

    // 定位文件树节点（修改：从Entry中获取File对象）
    private void locateFileInTree(File targetFile) {
        DefaultMutableTreeNode rootNode = (DefaultMutableTreeNode) treeModel.getRoot();
        List<TreePath> paths = new ArrayList<>();
        findNodePath(rootNode, targetFile, paths);
        if (!paths.isEmpty()) {
            fileTree.setSelectionPath(paths.get(0));
            fileTree.scrollPathToVisible(paths.get(0));
        }
    }

    // 查找节点路径（修改：从Entry中获取File对象）
    private void findNodePath(DefaultMutableTreeNode node, File targetFile, List<TreePath> paths) {
        for (int i = 0; i < node.getChildCount(); i++) {
            DefaultMutableTreeNode childNode = (DefaultMutableTreeNode) node.getChildAt(i);
            Object userObj = childNode.getUserObject();

            // 核心修改：从Entry中获取File对象
            File nodeFile = null;
            if (userObj instanceof Map.Entry) {
                nodeFile = (File) ((Map.Entry<?, ?>) userObj).getValue();
            }

            if (nodeFile != null) {
                if (nodeFile.getAbsolutePath().equals(targetFile.getAbsolutePath())) {
                    paths.add(new TreePath(childNode.getPath()));
                    return;
                }
                if (nodeFile.isDirectory()) {
                    findNodePath(childNode, targetFile, paths);
                }
            }
        }
    }

    // 占位符工具方法（保持不变）
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

    // 新增：美化文件内容（JSON/JS/HTML/CSS 全格式美化，提升可读性）
    private String beautifyContent(String content, String fileName) {
        if (content == null || content.isEmpty() || fileName == null) return content;
        String lowerName = fileName.toLowerCase();
        // 不限制文件大小（已通过 SwingWorker 后台线程 + isBinary 拦截 + 超时熔断兜底）
        // 新增：通用二进制文件检测——任一扩展名+前 2KB 含 NUL 字符即视为二进制
        if (looksLikeBinary(content)) return content;
        // 直接同步调用（已经在 SwingWorker 后台线程，无需再嵌套 Thread）
        try {
            String beautified = doBeautify(content, lowerName);
            int newlineInBeautified = beautified.length() - beautified.replace("\n", "").length();
            int newlineInOriginal = content.length() - content.replace("\n", "").length();
            montoyaApi.logging().logToError("[WxapkgFileBrowser] beautifyContent: 文件=" + fileName + " | 原长度=" + content.length() + " | 美化后长度=" + beautified.length() + " | 原换行=" + newlineInOriginal + " | 美化后换行=" + newlineInBeautified + " | 美化后前300字符=" + beautified.substring(0, Math.min(300, beautified.length())).replace("\n", "[\\n]"));
            return beautified;
        } catch (Throwable e) {
            montoyaApi.logging().logToError("[WxapkgFileBrowser] beautifyContent 出错: " + e.getMessage());
            return content;
        }
    }

    private String doBeautify(String content, String lowerName) {
        try {
            // JSON：Jackson 标准格式化
            if (lowerName.endsWith(".json")) {
                ObjectMapper mapper = new ObjectMapper();
                Object jsonObj = mapper.readValue(content, Object.class);
                return mapper.writerWithDefaultPrettyPrinter().writeValueAsString(jsonObj);
            }
            // JS：基于关键字+花括号深度，输出真正缩进的代码
            if (lowerName.endsWith(".js")) {
                return beautifyJs(content);
            }
            // HTML/WXML：使用简易标签解析器（避免引入 jsoup）
            if (lowerName.endsWith(".html") || lowerName.endsWith(".htm") || lowerName.endsWith(".wxml")) {
                return beautifyHtml(content);
            }
            // WXSS / CSS：基于 { } ; 美化并缩进
            if (lowerName.endsWith(".wxss") || lowerName.endsWith(".css")) {
                return beautifyCss(content);
            }
        } catch (Exception e) {
            return content;
        }
        return content;
    }

    // 新增：通用二进制文件检测——前 2KB 中 NUL 字符超过 3% 视为二进制
    private boolean looksLikeBinary(String content) {
        int checkLen = Math.min(content.length(), 2048);
        if (checkLen == 0) return false;
        int nullCount = 0;
        for (int i = 0; i < checkLen; i++) {
            if (content.charAt(i) == '\0') nullCount++;
        }
        return nullCount > checkLen * 0.03;
    }

    // 新增：基于 lines 列表检测二进制（仅看 NUL 字符，单行长度不算——混淆 JS 可能很长）
    private boolean looksLikeBinaryFromLines(List<String> lines) {
        int checkCount = Math.min(lines.size(), 20);
        int totalChars = 0;
        int nullCount = 0;
        for (int i = 0; i < checkCount; i++) {
            String line = lines.get(i);
            int scanLen = Math.min(line.length(), 100);
            for (int j = 0; j < scanLen; j++) {
                if (line.charAt(j) == '\0') nullCount++;
                totalChars++;
            }
        }
        return totalChars > 0 && nullCount > totalChars * 0.03;
    }

    // 新增：JS 美化器——关键字断行+花括号深度缩进
    private String beautifyJs(String content) {
        // 第一步：预处理——给压缩代码插入空格（让关键字识别能正确断行）
        int originalLen = content.length();
        content = preprocessMinifiedJs(content);
        montoyaApi.logging().logToError("[beautifyJs] 预处理: 原长=" + originalLen + " → 预处理后=" + content.length());

        // JS关键字集合（在匹配时断行到下一行）
        String[] KEYWORDS = {"function", "var", "let", "const", "if", "else", "for", "while",
                "do", "return", "case", "default", "try", "catch", "finally", "throw", "new",
                "typeof", "instanceof", "in", "of", "switch", "break", "continue", "delete",
                "void", "yield", "await", "async", "class", "extends", "import", "export",
                "static", "get", "set", "with", "debugger"};
        StringBuilder pattern = new StringBuilder("(?<![\\w$])(");
        for (int i = 0; i < KEYWORDS.length; i++) {
            if (i > 0) pattern.append("|");
            pattern.append(KEYWORDS[i]);
        }
        pattern.append(")(?![\\w$])");
        java.util.regex.Pattern kwPattern = java.util.regex.Pattern.compile(pattern.toString());

        StringBuilder out = new StringBuilder(content.length() * 3 / 2 + 256);
        int len = content.length();
        int braceDepth = 0;       // {} 深度（用于缩进）
        int parenDepth = 0;       // () 深度（关键字后跟 ( 不换行）
        boolean inString = false;
        char stringChar = 0;
        boolean inSingleComment = false;
        boolean inBlockComment = false;
        boolean needIndent = true; // 行首需要缩进

        // 先处理关键字插入换行（一次性扫描）
        // 注意：必须跳过字符串/注释内的关键字
        // 为简化：在主循环里识别关键字边界

        for (int i = 0; i < len; i++) {
            try {
            // 新增：响应中断（防止超时熔断无效）
            if (Thread.currentThread().isInterrupted()) return content;
            // 新增：单行超 10000 字符给个软警告，但不放弃美化（否则反编译后的长行就直接跳过了）
            if (i > 0 && content.charAt(i-1) == '\n' && (i + 10000 < len)) {
                int nextNewline = content.indexOf('\n', i);
                if (nextNewline > i && nextNewline - i > 10000) {
                    // 软警告：插入换行+省略号提示，但不return
                    if (out.length() > 0 && out.charAt(out.length() - 1) != '\n') out.append('\n');
                    out.append("/* ... 该行过长省略 ... */\n");
                    i = nextNewline; // 跳过这一行
                    continue;
                }
            }
            char c = content.charAt(i);
            char next = (i + 1 < len) ? content.charAt(i + 1) : '\0';

            // 块注释
            if (inBlockComment) {
                out.append(c);
                if (c == '*' && next == '/') {
                    out.append(next);
                    i++;
                    inBlockComment = false;
                }
                if (c == '\n') { needIndent = true; inBlockComment = false; }
                continue;
            }
            // 新增：压缩混淆代码自动换行——连续 500 字符无空白就强制换行
            if (!inString && !Character.isWhitespace(c) && i > 0) {
                int lastWs = -1;
                for (int back = i - 1; back >= Math.max(0, i - 500); back--) {
                    char bc = content.charAt(back);
                    if (Character.isWhitespace(bc)) { lastWs = back; break; }
                }
                if (lastWs >= 0 && i - lastWs > 500) {
                    // 在 i 处插入换行
                    if (out.length() > 0 && out.charAt(out.length() - 1) != '\n') out.append('\n');
                    appendIndent(out, braceDepth);
                    needIndent = false;
                }
            }
            // 单行注释
            if (inSingleComment) {
                out.append(c);
                if (c == '\n') {
                    inSingleComment = false;
                    needIndent = true;
                }
                continue;
            }
            // 字符串
            if (inString) {
                out.append(c);
                if (c == '\\' && next != '\0') { out.append(next); i++; continue; }
                if (c == stringChar) inString = false;
                continue;
            }
            // 进入字符串
            if (c == '"' || c == '\'' || c == '`') {
                out.append(c);
                inString = true; stringChar = c;
                continue;
            }
            // 进入单行注释
            if (c == '/' && next == '/') {
                out.append("//"); i++;
                inSingleComment = true;
                continue;
            }
            // 进入块注释
            if (c == '/' && next == '*') {
                out.append("/*"); i++;
                inBlockComment = true;
                continue;
            }
            // 花括号：换行+调整深度+下一行缩进
            if (c == '{') {
                if (out.length() > 0 && out.charAt(out.length() - 1) != '\n') out.append('\n');
                appendIndent(out, braceDepth);
                out.append('{');
                braceDepth++;
                out.append('\n');
                needIndent = true;
                continue;
            }
            if (c == '}') {
                braceDepth = Math.max(0, braceDepth - 1);
                // 闭合括号：换行并减少
                if (out.length() > 0 && out.charAt(out.length() - 1) != '\n') out.append('\n');
                appendIndent(out, braceDepth);
                out.append('}');
                // 修复：如果 } 后面紧跟 ; , ) 等符号，不换行（让 ; }, ) 跟在 } 后面）
                char nextAfter = (i + 1 < len) ? content.charAt(i + 1) : '\0';
                if (nextAfter == ';' || nextAfter == ',' || nextAfter == ')' || nextAfter == '.') {
                    // 不换行
                    needIndent = false;
                } else {
                    out.append('\n');
                    needIndent = true;
                }
                continue;
            }
            // 分号：换行（仅在非空括号场景下）
            if (c == ';' && parenDepth == 0) {
                out.append(';');
                // 修复：; 后跟 ) 或 } 或 ] 等时不换行（避免 ;换行 后下一行是 }) ）
                char nextAfter = (i + 1 < len) ? content.charAt(i + 1) : '\0';
                if (nextAfter == ')' || nextAfter == ']' || nextAfter == '}') {
                    // 不换行
                    needIndent = false;
                } else {
                    out.append('\n');
                    needIndent = true;
                }
                continue;
            }
            // 逗号：保留
            if (c == '(') { out.append(c); parenDepth++; continue; }
            if (c == ')') { out.append(c); parenDepth = Math.max(0, parenDepth - 1); continue; }

            // 关键字检测（仅在标识符上下文）
            if (Character.isLetter(c) || c == '_' || c == '$') {
                int start = i;
                while (i < len && (Character.isLetterOrDigit(content.charAt(i)) || content.charAt(i) == '_' || content.charAt(i) == '$')) i++;
                String word = content.substring(start, i);
                i--; // for 循环会 i++
                // 检测是否是关键字
                if (kwPattern.matcher(word).matches()) {
                    // 关键字前：如果是 ( 或 . 或 ! 等修饰符后跟的关键字（typeof/instanceof/in/of），不换行
                    boolean isAfterParen = out.length() > 0 && (out.charAt(out.length() - 1) == '(' || out.charAt(out.length() - 1) == '.' || out.charAt(out.length() - 1) == '!' || out.charAt(out.length() - 1) == ',');
                    if (!isAfterParen && out.length() > 0 && out.charAt(out.length() - 1) != '\n') out.append('\n');
                    if (!isAfterParen) appendIndent(out, braceDepth);
                    out.append(word);
                    // 关键字后如果是 ( 则不换行；如果是 { 也行
                    char nextAfter = (i + 1 < len) ? content.charAt(i + 1) : '\0';
                    if (nextAfter == '{') {
                        // 紧跟 { 时让 { 来负责换行
                    } else if (nextAfter == '(') {
                        // 紧跟 ( 不换行
                    } else {
                        out.append(' ');
                    }
                    needIndent = false;
                } else {
                    // 普通标识符：必要时先缩进
                    if (needIndent) {
                        appendIndent(out, braceDepth);
                        needIndent = false;
                    }
                    out.append(word);
                }
                continue;
            }

            // 行首需要缩进
            if (needIndent && !Character.isWhitespace(c)) {
                appendIndent(out, braceDepth);
                needIndent = false;
            }

            // 普通字符
            out.append(c);
            // 如果是 \n 准备下一行的缩进
            if (c == '\n') needIndent = true;
            } catch (Throwable ex) {
                montoyaApi.logging().logToError("[beautifyJs] 主循环 i=" + i + " 异常: " + ex.getClass().getSimpleName() + " | " + ex.getMessage() + " | stack=" + ex.getStackTrace()[0]);
                return content;
            }
        }
        montoyaApi.logging().logToError("[beautifyJs] 主循环跑完 out 长度=" + out.length());

        // 清理：连续空行压缩为单空行
        String result;
        try {
            result = out.toString();
            result = result.replaceAll("\n{3,}", "\n\n");
        } catch (Throwable ex) {
            montoyaApi.logging().logToError("[beautifyJs] 主循环异常: " + ex.getClass().getSimpleName() + " | " + ex.getMessage() + " | stack=" + ex.getStackTrace()[0]);
            return content;
        }
        int beautifiedNewlines = result.length() - result.replace("\n", "").length();
        montoyaApi.logging().logToError("[beautifyJs] 完成: 输出长=" + result.length() + " | 换行数=" + beautifiedNewlines);
        return result;
    }

    // 缩进辅助
    private void appendIndent(StringBuilder sb, int depth) {
        for (int i = 0; i < depth; i++) sb.append("  ");
    }

    // 新增：压缩 JS 预处理——给 {} ; , : 等符号前后插入空格（让关键字检测能正确识别）
    private String preprocessMinifiedJs(String content) {
        if (content == null || content.isEmpty()) return content;
        StringBuilder sb = new StringBuilder(content.length() + 256);
        int len = content.length();
        boolean inString = false;
        char stringChar = 0;
        boolean inSingleComment = false;
        boolean inBlockComment = false;
        for (int i = 0; i < len; i++) {
            char c = content.charAt(i);
            char prev = (i > 0) ? content.charAt(i - 1) : ' ';
            char next = (i + 1 < len) ? content.charAt(i + 1) : ' ';
            if (inBlockComment) {
                sb.append(c);
                if (c == '*' && next == '/') { sb.append(next); i++; inBlockComment = false; }
                continue;
            }
            if (inSingleComment) {
                sb.append(c);
                if (c == '\n') inSingleComment = false;
                continue;
            }
            if (inString) {
                sb.append(c);
                if (c == '\\' && next != '\0') { sb.append(next); i++; continue; }
                if (c == stringChar) inString = false;
                continue;
            }
            // 进入字符串
            if (c == '"' || c == '\'' || c == '`') {
                sb.append(c);
                inString = true; stringChar = c;
                continue;
            }
            // 单行注释
            if (c == '/' && next == '/') {
                sb.append("//"); i++;
                inSingleComment = true;
                continue;
            }
            // 块注释
            if (c == '/' && next == '*') {
                sb.append("/*"); i++;
                inBlockComment = true;
                continue;
            }
            // 处理符号：在 { } ; , : 前后插入空格（如果前后不是空白）
            if (c == '{' || c == '}' || c == ';' || c == ',' || c == ':') {
                if (!Character.isWhitespace(prev) && prev != '(' && prev != '[') sb.append(' ');
                sb.append(c);
                if (!Character.isWhitespace(next) && next != ')' && next != ']' && next != ',') sb.append(' ');
                continue;
            }
            sb.append(c);
        }
        return sb.toString();
    }

    // 新增：CSS 美化
    private String beautifyCss(String content) {
        StringBuilder out = new StringBuilder(content.length() * 3 / 2 + 256);
        int len = content.length();
        int braceDepth = 0;
        boolean inString = false;
        char stringChar = 0;
        boolean inSingleComment = false;
        boolean needIndent = true;

        for (int i = 0; i < len; i++) {
            if (Thread.currentThread().isInterrupted()) return content;
            char c = content.charAt(i);
            char next = (i + 1 < len) ? content.charAt(i + 1) : '\0';
            if (inSingleComment) {
                out.append(c);
                if (c == '\n') { inSingleComment = false; needIndent = true; }
                continue;
            }
            if (inString) {
                out.append(c);
                if (c == '\\' && next != '\0') { out.append(next); i++; continue; }
                if (c == stringChar) inString = false;
                continue;
            }
            if (c == '"' || c == '\'') {
                out.append(c); inString = true; stringChar = c; continue;
            }
            if (c == '{') {
                if (out.length() > 0 && out.charAt(out.length() - 1) != '\n') out.append('\n');
                appendIndent(out, braceDepth);
                out.append("{\n");
                braceDepth++;
                needIndent = true;
                continue;
            }
            if (c == '}') {
                braceDepth = Math.max(0, braceDepth - 1);
                out.append('\n');
                appendIndent(out, braceDepth);
                out.append("}\n");
                needIndent = true;
                continue;
            }
            if (c == ';' && !inString) {
                out.append(";\n");
                needIndent = true;
                continue;
            }
            if (needIndent && !Character.isWhitespace(c)) {
                appendIndent(out, braceDepth);
                needIndent = false;
            }
            out.append(c);
            if (c == '\n') needIndent = true;
        }
        return out.toString().replaceAll("\n{3,}", "\n\n");
    }

    // 新增：后台加载结果封装（美化后内容 + 高亮位置列表）
    private static class LoadResult {
        final String content;
        final List<Integer> matches;
        LoadResult(String content, List<Integer> matches) {
            this.content = content;
            this.matches = matches;
        }
    }

    // 新增：语法高亮——给关键字/字符串/注释/数字上色（VS Code 风格）
    private void applySyntaxHighlight(String content, String fileName, StyledDocument doc) {
        if (content == null || content.isEmpty()) return;
        // 仅对文本代码文件做高亮
        boolean isCode = fileName.endsWith(".js") || fileName.endsWith(".json")
                || fileName.endsWith(".html") || fileName.endsWith(".htm") || fileName.endsWith(".wxml")
                || fileName.endsWith(".css") || fileName.endsWith(".wxss");
        if (!isCode) return;
        // 限制大小避免大文件卡顿
        if (content.length() > 500 * 1024) return;

        // 定义颜色（VS Code Dark+ 主题色）
        Color KEYWORD = new Color(86, 156, 214);    // 蓝色：var/function/if/else 等
        Color STRING = new Color(206, 145, 120);     // 橙红色：字符串字面量
        Color COMMENT = new Color(106, 153, 85);     // 绿色：注释
        Color NUMBER = new Color(181, 206, 168);     // 浅绿：数字
        Color TAG = new Color(86, 156, 214);         // 蓝色：HTML标签
        Color ATTR = new Color(156, 220, 254);       // 浅蓝：HTML属性
        Color BUILTIN = new Color(197, 134, 192);    // 紫色：内置对象/函数

        // 关键字列表
        String[] JS_KW = {"var", "let", "const", "function", "return", "if", "else", "for",
                "while", "do", "switch", "case", "default", "break", "continue",
                "new", "delete", "typeof", "instanceof", "in", "of", "void",
                "try", "catch", "finally", "throw", "class", "extends", "super",
                "import", "export", "from", "as", "async", "await", "yield",
                "this", "true", "false", "null", "undefined", "with", "debugger"};
        String[] HTML_KW = {"html", "head", "body", "div", "span", "p", "a", "img", "script",
                "style", "link", "meta", "title", "h1", "h2", "h3", "h4", "h5", "h6",
                "input", "button", "form", "table", "tr", "td", "th", "ul", "ol", "li",
                "view", "text", "image", "block", "navigator", "wx:for", "wx:if"};

        // 创建样式
        Style keywordStyle = contentArea.addStyle("Kw", null);
        StyleConstants.setForeground(keywordStyle, KEYWORD);
        StyleConstants.setBold(keywordStyle, true);

        Style stringStyle = contentArea.addStyle("Str", null);
        StyleConstants.setForeground(stringStyle, STRING);

        Style commentStyle = contentArea.addStyle("Com", null);
        StyleConstants.setForeground(commentStyle, COMMENT);
        StyleConstants.setItalic(commentStyle, true);

        Style numberStyle = contentArea.addStyle("Num", null);
        StyleConstants.setForeground(numberStyle, NUMBER);

        Style tagStyle = contentArea.addStyle("Tag", null);
        StyleConstants.setForeground(tagStyle, TAG);

        Style attrStyle = contentArea.addStyle("Attr", null);
        StyleConstants.setForeground(attrStyle, ATTR);

        // 1. 高亮字符串（先处理，避免字符串内的关键字被误判）
        java.util.regex.Pattern strPattern = java.util.regex.Pattern.compile("\"([^\"\\\\]|\\\\.)*\"|'([^'\\\\]|\\\\.)*'|`([^`\\\\]|\\\\.)*`");
        java.util.regex.Matcher m = strPattern.matcher(content);
        while (m.find()) {
            doc.setCharacterAttributes(m.start(), m.end() - m.start(), stringStyle, false);
        }

        // 2. 高亮数字
        java.util.regex.Pattern numPattern = java.util.regex.Pattern.compile("\\b\\d+(\\.\\d+)?\\b");
        m = numPattern.matcher(content);
        while (m.find()) {
            // 不覆盖已经是字符串的范围（简单判断：前后有引号）
            if (m.start() > 0 && (content.charAt(m.start() - 1) == '"' || content.charAt(m.start() - 1) == '\'')) continue;
            doc.setCharacterAttributes(m.start(), m.end() - m.start(), numberStyle, false);
        }

        // 3. 高亮注释（// 单行 + /* */ 块）
        // 单行注释
        java.util.regex.Pattern lineComPattern = java.util.regex.Pattern.compile("//[^\\n]*");
        m = lineComPattern.matcher(content);
        while (m.find()) {
            doc.setCharacterAttributes(m.start(), m.end() - m.start(), commentStyle, false);
        }
        // 块注释
        java.util.regex.Pattern blockComPattern = java.util.regex.Pattern.compile("/\\*[\\s\\S]*?\\*/");
        m = blockComPattern.matcher(content);
        while (m.find()) {
            doc.setCharacterAttributes(m.start(), m.end() - m.start(), commentStyle, false);
        }
        // HTML 注释
        java.util.regex.Pattern htmlComPattern = java.util.regex.Pattern.compile("<!--[\\s\\S]*?-->");
        m = htmlComPattern.matcher(content);
        while (m.find()) {
            doc.setCharacterAttributes(m.start(), m.end() - m.start(), commentStyle, false);
        }

        // 4. 高亮 JS/JSON 关键字
        if (fileName.endsWith(".js") || fileName.endsWith(".json")) {
            StringBuilder kwPatternStr = new StringBuilder("\\b(");
            for (int i = 0; i < JS_KW.length; i++) {
                if (i > 0) kwPatternStr.append("|");
                kwPatternStr.append(JS_KW[i]);
            }
            kwPatternStr.append(")\\b");
            java.util.regex.Pattern kwP = java.util.regex.Pattern.compile(kwPatternStr.toString());
            m = kwP.matcher(content);
            while (m.find()) {
                doc.setCharacterAttributes(m.start(), m.end() - m.start(), keywordStyle, false);
            }
        }

        // 5. 高亮 HTML 标签
        if (fileName.endsWith(".html") || fileName.endsWith(".htm") || fileName.endsWith(".wxml")) {
            java.util.regex.Pattern tagP = java.util.regex.Pattern.compile("</?[a-zA-Z][a-zA-Z0-9-]*");
            m = tagP.matcher(content);
            while (m.find()) {
                int start = m.start();
                int end = m.end();
                doc.setCharacterAttributes(start, end - start, tagStyle, false);
            }
        }
    }

    // 新增：HTML/WXML 美化（标签前换行+缩进）
    private String beautifyHtml(String content) {
        StringBuilder out = new StringBuilder(content.length() * 3 / 2 + 256);
        int len = content.length();
        int tagDepth = 0;
        boolean inComment = false;
        boolean inString = false;
        char stringChar = 0;
        boolean needIndent = true;

        for (int i = 0; i < len; i++) {
            if (Thread.currentThread().isInterrupted()) return content;
            char c = content.charAt(i);
            char next = (i + 1 < len) ? content.charAt(i + 1) : '\0';

            if (inComment) {
                out.append(c);
                if (c == '-' && next == '-' && i + 2 < len && content.charAt(i + 2) == '>') {
                    out.append("-->\n");
                    i += 2;
                    inComment = false;
                    needIndent = true;
                } else if (c == '\n') {
                    needIndent = true;
                }
                continue;
            }
            if (inString) {
                out.append(c);
                if (c == stringChar) inString = false;
                continue;
            }

            // 注释开始
            if (c == '<' && i + 3 < len && content.charAt(i + 1) == '!' && content.charAt(i + 2) == '-' && content.charAt(i + 3) == '-') {
                if (out.length() > 0 && out.charAt(out.length() - 1) != '\n') out.append('\n');
                appendIndent(out, tagDepth);
                out.append("<!--");
                i += 3;
                inComment = true;
                continue;
            }
            // 开始标签
            if (c == '<' && next != '/' && next != '!') {
                // 提取标签名（到第一个非字母或 > / 空白前）
                int nameStart = i + 1;
                int nameEnd = nameStart;
                while (nameEnd < len) {
                    char nc = content.charAt(nameEnd);
                    if (Character.isLetterOrDigit(nc) || nc == '-') nameEnd++;
                    else break;
                }
                String tagName = content.substring(nameStart, nameEnd).toLowerCase();

                if (out.length() > 0 && out.charAt(out.length() - 1) != '\n') out.append('\n');
                appendIndent(out, tagDepth);
                tagDepth++;
                // 把整个开始标签原样输出（不破坏属性）
                while (i < len && content.charAt(i) != '>') {
                    out.append(content.charAt(i));
                    i++;
                }
                if (i < len) out.append('>');
                out.append('\n');
                needIndent = true;

                // === 新增：处理 <script> 和 <style> 的内嵌代码 ===
                if ("script".equals(tagName) || "style".equals(tagName)) {
                    // 查找结束标签
                    String closeTag = "</" + tagName + ">";
                    int closeIdx = findIgnoreCase(content, closeTag, i + 1);
                    if (closeIdx != -1) {
                        String inner = content.substring(i + 1, closeIdx);
                        String beautifiedInner;
                        if ("script".equals(tagName)) {
                            beautifiedInner = beautifyJs(inner);
                        } else {
                            beautifiedInner = beautifyCss(inner);
                        }
                        // 输出美化后的内嵌代码（缩进一级）
                        String[] innerLines = beautifiedInner.split("\n", -1);
                        for (String line : innerLines) {
                            if (line.isEmpty()) { out.append('\n'); continue; }
                            appendIndent(out, tagDepth);
                            out.append(line).append('\n');
                        }
                        // 跳过原始内嵌代码到 </script> 前
                        i = closeIdx + closeTag.length() - 1; // for 循环会 i++
                        // 闭合标签前的换行
                        if (out.length() > 0 && out.charAt(out.length() - 1) != '\n') out.append('\n');
                        appendIndent(out, tagDepth - 1);
                        out.append(closeTag).append('\n');
                        needIndent = true;
                    }
                }
                continue;
            }
            // 结束标签
            if (c == '<' && next == '/') {
                tagDepth = Math.max(0, tagDepth - 1);
                if (out.length() > 0 && out.charAt(out.length() - 1) != '\n') out.append('\n');
                appendIndent(out, tagDepth);
                // 输出整个结束标签
                while (i < len && content.charAt(i) != '>') {
                    out.append(content.charAt(i));
                    i++;
                }
                if (i < len) out.append('>');
                out.append('\n');
                needIndent = true;
                continue;
            }
            // 自闭合结尾
            if (c == '/' && next == '>') {
                out.append("/>\n");
                i++;
                tagDepth = Math.max(0, tagDepth - 1);
                needIndent = true;
                continue;
            }
            if (c == '>') {
                out.append(">\n");
                needIndent = true;
                continue;
            }
            // 进入属性字符串
            if (c == '"' || c == '\'') {
                out.append(c);
                inString = true; stringChar = c;
                continue;
            }

            if (needIndent && !Character.isWhitespace(c)) {
                appendIndent(out, tagDepth);
                needIndent = false;
            }
            out.append(c);
            if (c == '\n') needIndent = true;
        }
        return out.toString().replaceAll("\n{3,}", "\n\n");
    }

    // 新增：在 content 中从 fromIndex 开始查找 needle（忽略大小写），找不到返回 -1
    private int findIgnoreCase(String content, String needle, int fromIndex) {
        int max = content.length() - needle.length();
        if (fromIndex > max) return -1;
        String lower = content.toLowerCase();
        String lowerNeedle = needle.toLowerCase();
        for (int i = fromIndex; i <= max; i++) {
            if (lower.regionMatches(i, lowerNeedle, 0, lowerNeedle.length())) return i;
        }
        return -1;
    }
}