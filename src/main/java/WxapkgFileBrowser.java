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

/**
 * 独立文件浏览器窗口（支持搜索高亮+匹配数量+下一个定位，修复相对路径显示，新增高亮左右居中）
 */
public class WxapkgFileBrowser extends JFrame {
    private JTree fileTree;
    private JTextPane contentArea;  // 支持高亮
    private JTextField searchField;
    private JList<String> searchResultList;
    private DefaultTreeModel treeModel;
    private File currentRootDir;
    private String currentKeyword;      // 当前搜索关键词（用于高亮）
    private Path rootPath; // 根目录的标准化Path（计算相对路径）

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
        searchPanel.add(new JLabel("🔍 全局搜索："), BorderLayout.WEST);
        searchPanel.add(searchField, BorderLayout.CENTER);
        searchPanel.add(searchBtn, BorderLayout.EAST);

        // 中间内容区（左右分割）
        JSplitPane contentSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        contentSplit.setDividerLocation(400);
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

        fileTree.addTreeSelectionListener(e -> loadSelectedFileContent());
        JScrollPane treeScroll = new JScrollPane(fileTree);
        treeScroll.setBorder(BorderFactory.createTitledBorder("📂 反编译文件结构"));
        contentSplit.setLeftComponent(treeScroll);

        // 右侧：内容预览 + 搜索结果（上下分割）
        JSplitPane rightSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        rightSplit.setDividerLocation(500);
        rightSplit.setDividerSize(5);

        // ========== 新增：内容预览区 + 右下角匹配控制区 ==========
        JPanel contentPanel = new JPanel(new BorderLayout());
        contentArea = new JTextPane();
        contentArea.setEditable(false);
        contentArea.setFont(new Font("Consolas", Font.PLAIN, 16));
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

        // 组装内容预览区（内容+控制区）
        JScrollPane contentScroll = new JScrollPane(contentArea); // 单独定义滚动面板，方便后续获取
        contentPanel.add(contentScroll, BorderLayout.CENTER);
        contentPanel.add(matchControlPanel, BorderLayout.SOUTH);
        contentPanel.setBorder(BorderFactory.createTitledBorder("📄 文件内容"));
        rightSplit.setTopComponent(contentPanel);

        // 搜索结果区（保持不变）
        searchResultList = new JList<>();
        searchResultList.setFont(new Font("Microsoft YaHei", Font.PLAIN, 14));
        searchResultList.addListSelectionListener(e -> jumpToSearchResult());
        JScrollPane resultScroll = new JScrollPane(searchResultList);
        resultScroll.setBorder(BorderFactory.createTitledBorder("🔍 搜索结果"));
        rightSplit.setBottomComponent(resultScroll);

        contentSplit.setRightComponent(rightSplit);

        // 组装窗口
        add(searchPanel, BorderLayout.NORTH);
        add(contentSplit, BorderLayout.CENTER);
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
                montoyaApi.logging().logToOutput("buildTreeNodes:" + relativePath);

                String relativePathStr = relativePath.toString();
                montoyaApi.logging().logToOutput(relativePathStr);

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
        // 切换文件时，重置匹配状态
        currentMatchPositions.clear();
        currentMatchIndex = 0;
        matchCountLabel.setText("匹配数量：0");
        prevMatchBtn.setEnabled(false);
        nextMatchBtn.setEnabled(false);

        TreePath selectedPath = fileTree.getSelectionPath();
        if (selectedPath == null) return;
        DefaultMutableTreeNode selectedNode = (DefaultMutableTreeNode) selectedPath.getLastPathComponent();
        Object userObj = selectedNode.getUserObject();

        // 核心修改：从Entry中获取File对象
        File selectedFile = null;
        if (userObj instanceof Map.Entry) {
            selectedFile = (File) ((Map.Entry<?, ?>) userObj).getValue();
        }

        if (selectedFile == null || selectedFile.isDirectory()) {
            contentArea.setText("");
            return;
        }

        // 超大文件提示（保持不变）
        long fileSize = selectedFile.length();
        if (fileSize > 1024 * 1024 * 5) {
            JOptionPane.showMessageDialog(this, "文件超过5MB，暂不加载（避免卡顿）！", "提示", JOptionPane.WARNING_MESSAGE);
            return;
        }

        contentArea.setText("Loading...."); // 新增：标注编码

        // 异步读取（强制UTF-8 + 异常捕获）
        File finalSelectedFile = selectedFile;
        new SwingWorker<String, Void>() {
            @Override
            protected String doInBackground() throws Exception {
                StringBuilder contentSb = new StringBuilder();
                // 强制UTF-8读取（这一步已经得到正确的UTF-8字符串）
                try (BufferedReader br = new BufferedReader(
                        new InputStreamReader(new FileInputStream(finalSelectedFile), StandardCharsets.UTF_8))) {
                    String line;
                    while ((line = br.readLine()) != null) {
                        contentSb.append(line).append("\n");
                    }
                }
                // 处理UTF-8 BOM头（若文件开头有EF BB BF，去掉）
                String rawContent = contentSb.toString();
                if (rawContent.startsWith("\uFEFF")) {
                    rawContent = rawContent.substring(1);
                }
                return rawContent;
            }

            @Override
            protected void done() {
                try {
                    // 直接使用读取到的UTF-8字符串（无需重复转字节）
                    String utf8Content = get();
                    StyledDocument doc = contentArea.getStyledDocument();
                    doc.remove(0, doc.getLength());
                    doc.insertString(0, utf8Content, null);

                    // 高亮逻辑（保持不变，用utf8Content匹配）
                    if (currentKeyword != null && !currentKeyword.isEmpty()) {
                        Style highlightStyle = contentArea.addStyle("Highlight", null);
                        StyleConstants.setBackground(highlightStyle, Color.YELLOW);
                        StyleConstants.setForeground(highlightStyle, Color.RED);

                        int keywordLen = currentKeyword.length();
                        int pos = 0;
                        currentMatchPositions.clear();

                        while ((pos = utf8Content.indexOf(currentKeyword, pos)) != -1) {
                            currentMatchPositions.add(pos);
                            doc.setCharacterAttributes(pos, keywordLen, highlightStyle, false);
                            pos += keywordLen;
                        }

                        int matchCount = currentMatchPositions.size();
                        // 新增：更新匹配标签为 1/总数 格式
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
                }
            }
        }.execute();
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
                    montoyaApi.logging().logToOutput("文件" + file.getName() + "不支持UTF-8编码：" + e.getMessage());
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
}