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
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * MCP（Model Context Protocol）服务器核心
 *
 * 实现 MCP 2024-11-05 协议，通过 HTTP + SSE 传输：
 *  - GET  /sse                    建立 SSE 长连接（客户端从这里开始）
 *  - POST /message?sessionId=xxx  客户端发送 JSON-RPC 消息（SSE 响应）
 *  - POST / 或 /mcp               Streamable HTTP 模式（纯 JSON 响应）
 *
 * 给 AI 客户端（Trae / Claude Desktop / Cursor 等）提供微信小程序反编译能力：
 *  1. decompile_wxapkg       反编译指定小程序（wxapkg 文件或目录）
 *  2. list_decompiled_projects 列出已反编译的所有小程序
 *  3. list_wxapkg_files      扫描目录下的 wxapkg 文件
 *  4. get_decompiled_code    读取反编译后的代码（文件列表/文件内容）
 *  5. search_decompiled_code 在反编译代码中搜索关键字
 *  6. get_wxapkg_default_path 查询 wxapkg 默认打开路径
 *  7. list_wxapkg_folders    列出默认路径下所有文件夹的创建/修改时间等信息
 *  8. get_api_endpoints      提取反编译代码中的API接口列表
 *  9. get_domain_api_params  按域名提取接口、参数示例、加密方式与调用链
 */
public class McpServerCore {
    public static final String OUTPUT_DIR = System.getProperty("user.home") + File.separator + ".burp" + File.separator + "JaySenWxapkgOutput";
    private static final String PROTOCOL_VERSION = "2024-11-05";
    private static final int MAX_TEXT_CHARS = 120000;   // 单个响应文本上限
    private static final int MAX_LIST_ITEMS = 500;      // 列表类结果上限
    private static final int MAX_SEARCH_HITS = 200;     // 搜索命中上限
    // 文本文件扩展名白名单（搜索/扫描只处理这些）
    private static final Set<String> TEXT_EXTS = new HashSet<>(Arrays.asList(
            "js", "json", "wxml", "wxss", "html", "css", "txt", "md", "ts", "vue",
            "java", "php", "py", "xml", "wxs", "shtml", "map", "log"));

    private final ObjectMapper mapper = new ObjectMapper();
    private final Map<String, SseSession> sessions = new ConcurrentHashMap<>();
    private final AtomicLong sessionIdGen = new AtomicLong();
    private final Consumer<String> logSink;

    private volatile HttpServer server;
    private volatile int port = 0;
    private volatile boolean running = false;

    public McpServerCore(Consumer<String> logSink) {
        this.logSink = logSink != null ? logSink : s -> {};
    }

    public boolean isRunning() { return running; }
    public int getPort() { return port; }

    /** 启动服务（若已启动先停止） */
    public synchronized void start(int newPort) throws IOException {
        stop();
        // 仅绑定本机回环地址，避免局域网暴露
        HttpServer hs = HttpServer.create(new InetSocketAddress("127.0.0.1", newPort), 0);
        hs.createContext("/", this::rootHandler);
        hs.setExecutor(Executors.newCachedThreadPool());
        hs.start();
        this.server = hs;
        this.port = newPort;
        this.running = true;
        log("MCP Server 已启动：http://127.0.0.1:" + newPort + "/sse");
    }

    /** 停止服务 */
    public synchronized void stop() {
        if (server != null) {
            server.stop(0);
            server = null;
        }
        // 关闭所有SSE会话
        for (SseSession s : sessions.values()) {
            try { s.close(); } catch (Exception ignored) {}
        }
        sessions.clear();
        if (running) log("MCP Server 已停止");
        running = false;
    }

    private void log(String msg) { logSink.accept(msg); }

    // ==================== HTTP 入口 ====================

    private void rootHandler(HttpExchange ex) throws IOException {
        try {
            String method = ex.getRequestMethod().toUpperCase();
            String path = ex.getRequestURI().getPath();
            if ("GET".equals(method) && "/sse".equals(path)) {
                handleSseOpen(ex);
            } else if ("POST".equals(method) && "/message".equals(path)) {
                handleSsePost(ex);
            } else if ("POST".equals(method) && ("/".equals(path) || "/mcp".equals(path) || "/sse".equals(path))) {
                // 兼容把 /sse 当作 Streamable HTTP 端点直接 POST 的客户端
                handleStreamablePost(ex);
            } else if ("GET".equals(method) && ("/".equals(path) || "/health".equals(path))) {
                byte[] body = ("{\"ok\":true,\"server\":\"JaySenWxapkg-MCP\",\"protocol\":\"" + PROTOCOL_VERSION + "\"}").getBytes(StandardCharsets.UTF_8);
                ex.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
                ex.sendResponseHeaders(200, body.length);
                ex.getResponseBody().write(body);
                ex.close();
            } else {
                ex.sendResponseHeaders(404, -1);
                ex.close();
            }
        } catch (Exception e) {
            try { ex.sendResponseHeaders(500, -1); } catch (Exception ignored) {}
            ex.close();
        }
    }

    // ---------- SSE 传输 ----------

    private void handleSseOpen(HttpExchange ex) throws IOException {
        String sessionId = "s" + sessionIdGen.incrementAndGet();
        ex.getResponseHeaders().set("Content-Type", "text/event-stream; charset=utf-8");
        ex.getResponseHeaders().set("Cache-Control", "no-cache");
        ex.getResponseHeaders().set("Connection", "keep-alive");
        ex.sendResponseHeaders(200, 0); // chunked
        OutputStream out = ex.getResponseBody();
        out.write(("event: endpoint\ndata: /message?sessionId=" + sessionId + "\n\n").getBytes(StandardCharsets.UTF_8));
        out.flush();
        SseSession session = new SseSession(sessionId, ex, out);
        sessions.put(sessionId, session);
        log("新客户端已连接（session=" + sessionId + "）");
        // 保活循环，客户端断开时抛出异常退出
        try {
            while (!session.closed) {
                session.keepAlive();
                Thread.sleep(15000);
            }
        } catch (Exception e) {
            // 客户端断开
        } finally {
            sessions.remove(sessionId);
            session.close();
            log("客户端已断开（session=" + sessionId + "）");
        }
    }

    private void handleSsePost(HttpExchange ex) throws IOException {
        String sessionId = null;
        String query = ex.getRequestURI().getQuery();
        if (query != null) {
            for (String kv : query.split("&")) {
                if (kv.startsWith("sessionId=")) {
                    sessionId = kv.substring("sessionId=".length());
                    break;
                }
            }
        }
        SseSession session = sessionId == null ? null : sessions.get(sessionId);
        if (session == null) {
            writeJsonResponse(ex, 404, buildError(null, -32000, "SSE会话不存在或已断开：" + sessionId));
            return;
        }
        String raw = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        JsonNode req;
        try {
            req = mapper.readTree(raw);
        } catch (Exception e) {
            writeJsonResponse(ex, 400, buildError(null, -32700, "无效的JSON请求"));
            return;
        }
        if (req == null || !req.isObject()) {
            writeJsonResponse(ex, 400, buildError(null, -32600, "请求必须是JSON对象"));
            return;
        }
        // 按 MCP SSE 规范：POST 只回 202 Accepted，JSON-RPC 响应通过 SSE 通道推送
        byte[] accepted = "Accepted".getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
        ex.sendResponseHeaders(202, accepted.length);
        ex.getResponseBody().write(accepted);
        ex.close();
        // 通知类消息（无id）不需要响应
        if (!req.has("id")) return;
        ObjectNode resp = dispatch((ObjectNode) req);
        session.send(mapper.writeValueAsString(resp));
    }

    // ---------- Streamable HTTP ----------

    private void handleStreamablePost(HttpExchange ex) throws IOException {
        String raw = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        JsonNode req;
        try {
            req = mapper.readTree(raw);
        } catch (Exception e) {
            writeJsonResponse(ex, 400, buildError(null, -32700, "无效的JSON请求"));
            return;
        }
        if (req == null || !req.isObject()) {
            writeJsonResponse(ex, 400, buildError(null, -32600, "请求必须是JSON对象"));
            return;
        }
        if (!req.has("id")) {
            ex.sendResponseHeaders(202, -1);
            ex.close();
            return;
        }
        ObjectNode resp = dispatch((ObjectNode) req);
        writeJsonResponse(ex, 200, resp);
    }

    private void writeJsonResponse(HttpExchange ex, int code, ObjectNode resp) throws IOException {
        byte[] body = mapper.writeValueAsBytes(resp);
        ex.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        ex.sendResponseHeaders(code, body.length);
        ex.getResponseBody().write(body);
        ex.close();
    }

    // ==================== JSON-RPC 分发 ====================

    private ObjectNode dispatch(ObjectNode req) {
        JsonNode idNode = req.get("id");
        String method = req.has("method") ? req.path("method").asText("") : "";
        ObjectNode resp = mapper.createObjectNode();
        resp.put("jsonrpc", "2.0");
        resp.set("id", idNode);
        try {
            switch (method) {
                case "initialize":
                    resp.set("result", buildInitializeResult());
                    break;
                case "ping":
                    resp.set("result", mapper.createObjectNode());
                    break;
                case "tools/list":
                    resp.set("result", buildToolsListResult());
                    break;
                case "tools/call":
                    resp.set("result", callTool(req));
                    break;
                default:
                    return buildError(idNode, -32601, "未知方法：" + method);
            }
        } catch (Exception e) {
            return buildError(idNode, -32603, "内部错误：" + e.getMessage());
        }
        return resp;
    }

    private ObjectNode buildError(JsonNode idNode, int code, String message) {
        ObjectNode resp = mapper.createObjectNode();
        resp.put("jsonrpc", "2.0");
        if (idNode != null) resp.set("id", idNode); else resp.putNull("id");
        ObjectNode err = resp.putObject("error");
        err.put("code", code);
        err.put("message", message);
        return resp;
    }

    private ObjectNode buildInitializeResult() {
        ObjectNode result = mapper.createObjectNode();
        result.put("protocolVersion", PROTOCOL_VERSION);
        ObjectNode capabilities = result.putObject("capabilities");
        capabilities.putObject("tools");
        ObjectNode serverInfo = result.putObject("serverInfo");
        serverInfo.put("name", "JaySenWxapkg-MCP");
        serverInfo.put("version", "3.0");
        return result;
    }

    private ObjectNode buildToolsListResult() {
        ObjectNode result = mapper.createObjectNode();
        ArrayNode tools = result.putArray("tools");
        tools.add(tool("decompile_wxapkg", "反编译指定小程序：输入wxapkg文件路径或包含wxapkg文件的目录，自动识别加密包并解密，解包后返回小程序信息、API接口列表和敏感信息。",
                schemaBuilder().required("path")
                        .prop("path", "string", "wxapkg文件路径，或包含wxapkg文件的目录路径")
                        .prop("extract_api", "boolean", "是否提取API接口，默认true")
                        .prop("detect_sensitive", "boolean", "是否检测敏感信息，默认true").build()));
        tools.add(tool("list_decompiled_projects", "列出所有已反编译的小程序项目（输出目录中的appid文件夹）。",
                schemaBuilder().build()));
        tools.add(tool("list_wxapkg_files", "扫描指定目录（递归），列出所有wxapkg文件及大小。",
                schemaBuilder().required("path")
                        .prop("path", "string", "要扫描的目录路径").build()));
        tools.add(tool("get_decompiled_code", "读取反编译后的小程序代码：不填file参数时返回项目文件列表；填file参数时返回该文件内容（自动截断大文件）。",
                schemaBuilder().required("project")
                        .prop("project", "string", "项目名（appid）或反编译输出目录的绝对路径")
                        .prop("file", "string", "相对文件路径，如 app.js、pages/index/index.js，省略则列出文件列表")
                        .prop("max_chars", "number", "文件内容最大字符数，默认50000").build()));
        tools.add(tool("search_decompiled_code", "在反编译后的小程序代码中搜索关键字（支持正则），返回命中文件、行号和内容。",
                schemaBuilder().required("project", "keyword")
                        .prop("project", "string", "项目名（appid）或反编译输出目录的绝对路径")
                        .prop("keyword", "string", "搜索关键字")
                        .prop("regex", "boolean", "是否按正则表达式搜索，默认false").build()));
        tools.add(tool("get_wxapkg_default_path", "查询插件配置的wxapkg默认打开路径，并统计该路径下的一级文件夹数和wxapkg文件数。",
                schemaBuilder().build()));
        tools.add(tool("list_wxapkg_folders", "列出wxapkg目录下所有一级文件夹的创建时间、修改时间、文件数和wxapkg数量。不传path时使用插件配置的默认打开路径。",
                schemaBuilder()
                        .prop("path", "string", "要扫描的目录路径，省略则使用默认打开路径").build()));
        tools.add(tool("get_api_endpoints", "提取指定小程序反编译代码中的API接口列表（使用插件配置的API正则），返回去重后的URL、出现次数和首次出现位置。",
                schemaBuilder()
                        .prop("project", "string", "项目名（appid）或反编译输出目录的绝对路径")
                        .prop("max_items", "number", "最多返回条数，默认300").build()));
        tools.add(tool("get_domain_api_params", "按域名提取该域名的所有接口及请求参数示例（静态分析反编译代码）：返回接口URL、请求方法、参数键、示例参数、请求头键、加密方式、页面/方法调用链和源码片段。",
                schemaBuilder().required("domain")
                        .prop("domain", "string", "目标域名，如 www.webstr.top（也可传完整URL）")
                        .prop("project", "string", "限定项目（appid或输出目录），省略则扫描所有已反编译项目")
                        .prop("max_items", "number", "最多返回接口数，默认50").build()));
        return result;
    }

    private ObjectNode tool(String name, String description, ObjectNode inputSchema) {
        ObjectNode t = mapper.createObjectNode();
        t.put("name", name);
        t.put("description", description);
        t.set("inputSchema", inputSchema);
        return t;
    }

    // 简化schema构造器
    private SchemaBuilder schemaBuilder() { return new SchemaBuilder(); }

    private static class SchemaBuilder {
        private final ObjectNode schema;
        private final ObjectNode props;
        private final ArrayNode required;
        SchemaBuilder() {
            schema = new ObjectMapper().createObjectNode();
            schema.put("type", "object");
            props = schema.putObject("properties");
            required = schema.putArray("required");
        }
        SchemaBuilder prop(String name, String type, String desc) {
            ObjectNode p = props.putObject(name);
            p.put("type", type);
            p.put("description", desc);
            return this;
        }
        SchemaBuilder required(String... names) {
            for (String n : names) required.add(n);
            return this;
        }
        ObjectNode build() { return schema; }
    }

    // ==================== 工具执行 ====================

    private ObjectNode callTool(ObjectNode req) {
        String name = req.path("params").path("name").asText("");
        JsonNode args = req.path("params").get("arguments");
        if (args == null || !args.isObject()) args = mapper.createObjectNode();
        log("调用工具：" + name + " 参数=" + args);
        String text;
        boolean isError = false;
        try {
            switch (name) {
                case "decompile_wxapkg": text = toolDecompile(args); break;
                case "list_decompiled_projects": text = toolListProjects(); break;
                case "list_wxapkg_files": text = toolListWxapkg(args); break;
                case "get_decompiled_code": text = toolGetCode(args); break;
                case "search_decompiled_code": text = toolSearch(args); break;
                case "get_wxapkg_default_path": text = toolDefaultPath(); break;
                case "list_wxapkg_folders": text = toolListFolders(args); break;
                case "get_api_endpoints": text = toolApiList(args); break;
                case "get_domain_api_params": text = toolDomainApiParams(args); break;
                default:
                    throw new IllegalArgumentException("未知工具：" + name);
            }
        } catch (Exception e) {
            text = "工具执行失败：" + e.getMessage();
            isError = true;
        }
        ObjectNode result = mapper.createObjectNode();
        ArrayNode content = result.putArray("content");
        ObjectNode item = content.addObject();
        item.put("type", "text");
        item.put("text", truncate(text, MAX_TEXT_CHARS));
        result.put("isError", isError);
        return result;
    }

    // ---------- 工具1：反编译 ----------

    private String toolDecompile(JsonNode args) throws Exception {
        String pathStr = args.path("path").asText("").trim();
        if (pathStr.isEmpty()) throw new IllegalArgumentException("缺少参数 path");
        boolean extractApi = !args.has("extract_api") || args.path("extract_api").asBoolean(true);
        boolean detectSensitive = !args.has("detect_sensitive") || args.path("detect_sensitive").asBoolean(true);

        List<File> files = new ArrayList<>();
        File f = new File(pathStr);
        if (!f.exists()) throw new IllegalArgumentException("路径不存在：" + pathStr);
        if (f.isFile()) {
            if (!f.getName().toLowerCase().endsWith(".wxapkg")) throw new IllegalArgumentException("不是wxapkg文件：" + pathStr);
            files.add(f);
        } else {
            scanWxapkgRecursive(f, files);
            if (files.isEmpty()) throw new IllegalArgumentException("目录下未找到wxapkg文件：" + pathStr);
        }

        Config.SavedConfig cfg = Config.loadConfigFile();
        Pattern apiPattern = compileOr(cfg.getApiRegex(), Config.DEFAULT_API_PATTERN);
        Map<String, Pattern> sensitivePatterns = buildSensitivePatterns(cfg);

        StringBuilder sb = new StringBuilder();
        sb.append("共发现 ").append(files.size()).append(" 个wxapkg文件\n");
        for (File wxapkg : files) {
            sb.append("\n========== ").append(wxapkg.getName()).append(" ==========\n");
            WxAppletDecompiler dec = new WxAppletDecompiler(
                    wxapkg.getAbsolutePath(), OUTPUT_DIR, 5,
                    apiPattern, sensitivePatterns,
                    cfg.getSuffixBlacklist(), cfg.getPrefixBlacklist());
            dec.execute();
            for (WxAppletDecompiler.AppInfo info : dec.getAppInfoList()) {
                sb.append(info.getKey()).append("：").append(info.getValue()).append("\n");
            }
            if (extractApi) {
                List<WxAppletDecompiler.ApiInfo> apis = dedupApis(dec.getApiInfoList());
                sb.append("API接口数：").append(apis.size()).append("\n");
                int cap = Math.min(apis.size(), MAX_LIST_ITEMS);
                for (int i = 0; i < cap; i++) {
                    WxAppletDecompiler.ApiInfo api = apis.get(i);
                    sb.append("  [").append(i + 1).append("] ").append(api.getApi())
                      .append("  (来源: ").append(api.getFile()).append(")\n");
                }
                if (apis.size() > cap) sb.append("  ... 其余 ").append(apis.size() - cap).append(" 条已省略\n");
            }
            if (detectSensitive) {
                List<WxAppletDecompiler.SensitiveInfo> sens = dec.getSensitiveInfoList();
                sb.append("敏感信息数：").append(sens.size()).append("\n");
                int cap = Math.min(sens.size(), MAX_LIST_ITEMS);
                for (int i = 0; i < cap; i++) {
                    WxAppletDecompiler.SensitiveInfo s = sens.get(i);
                    sb.append("  [").append(s.getType()).append("] ").append(s.getContent())
                      .append("  (文件: ").append(s.getFile()).append(")\n");
                }
                if (sens.size() > cap) sb.append("  ... 其余 ").append(sens.size() - cap).append(" 条已省略\n");
            }
        }
        return sb.toString();
    }

    // ---------- 工具2：列出项目 ----------

    private String toolListProjects() {
        File outDir = new File(OUTPUT_DIR);
        StringBuilder sb = new StringBuilder();
        if (!outDir.exists() || !outDir.isDirectory()) {
            return "输出目录不存在：" + OUTPUT_DIR + "（尚未反编译过任何小程序）";
        }
        File[] dirs = outDir.listFiles(File::isDirectory);
        sb.append("输出目录：").append(OUTPUT_DIR).append("\n");
        if (dirs == null || dirs.length == 0) return sb.append("（空）").toString();
        Arrays.sort(dirs, Comparator.comparingLong(File::lastModified).reversed());
        for (File d : dirs) {
            long fileCount = countFiles(d);
            sb.append("- ").append(d.getName())
              .append("  文件数:").append(fileCount)
              .append("  修改时间:").append(new java.util.Date(d.lastModified())).append("\n");
        }
        return sb.toString();
    }

    // ---------- 工具3：扫描wxapkg ----------

    private String toolListWxapkg(JsonNode args) {
        String pathStr = args.path("path").asText("").trim();
        if (pathStr.isEmpty()) throw new IllegalArgumentException("缺少参数 path");
        File f = new File(pathStr);
        if (!f.exists()) throw new IllegalArgumentException("路径不存在：" + pathStr);
        List<File> files = new ArrayList<>();
        if (f.isDirectory()) scanWxapkgRecursive(f, files);
        else if (f.getName().toLowerCase().endsWith(".wxapkg")) files.add(f);
        StringBuilder sb = new StringBuilder();
        if (files.isEmpty()) return "未找到wxapkg文件";
        sb.append("共找到 ").append(files.size()).append(" 个wxapkg文件：\n");
        for (File w : files) {
            sb.append("- ").append(w.getAbsolutePath()).append("  (").append(w.length() / 1024).append(" KB)\n");
        }
        return sb.toString();
    }

    // ---------- 工具4：读取代码 ----------

    private String toolGetCode(JsonNode args) throws IOException {
        String project = args.path("project").asText("").trim();
        if (project.isEmpty()) throw new IllegalArgumentException("缺少参数 project");
        int maxChars = args.has("max_chars") ? args.path("max_chars").asInt(50000) : 50000;
        maxChars = Math.max(1000, Math.min(maxChars, 500000));
        Path base = resolveProject(project);

        String fileParam = args.path("file").asText("").trim();
        if (fileParam.isEmpty()) {
            StringBuilder sb = new StringBuilder();
            sb.append("项目：").append(base.toAbsolutePath()).append("\n文件列表：\n");
            List<Path> all = new ArrayList<>();
            Files.walk(base).filter(Files::isRegularFile).forEach(all::add);
            all.sort(Comparator.comparing(p -> base.relativize(p).toString()));
            int cap = Math.min(all.size(), MAX_LIST_ITEMS);
            for (int i = 0; i < cap; i++) {
                Path p = all.get(i);
                String rel = base.relativize(p).toString().replace('\\', '/');
                long size = Files.size(p);
                sb.append("  ").append(rel).append("  (").append(size).append(" B)\n");
            }
            if (all.size() > cap) sb.append("  ... 其余 ").append(all.size() - cap).append(" 个文件已省略\n");
            return sb.toString();
        }
        Path target = safeResolve(base, fileParam);
        if (!Files.isRegularFile(target)) throw new IllegalArgumentException("文件不存在：" + fileParam);
        String content = new String(Files.readAllBytes(target), StandardCharsets.UTF_8);
        String truncated = truncate(content, maxChars);
        return "文件：" + fileParam + "\n大小：" + Files.size(target) + " 字节\n是否截断：" + (truncated.length() != content.length()) + "\n\n" + truncated;
    }

    // ---------- 工具5：搜索代码 ----------

    private String toolSearch(JsonNode args) throws IOException {
        String project = args.path("project").asText("").trim();
        String keyword = args.path("keyword").asText("");
        if (project.isEmpty()) throw new IllegalArgumentException("缺少参数 project");
        if (keyword.isEmpty()) throw new IllegalArgumentException("缺少参数 keyword");
        boolean regex = args.path("regex").asBoolean(false);
        Pattern pattern;
        try {
            pattern = regex ? Pattern.compile(keyword) : Pattern.compile(Pattern.quote(keyword));
        } catch (PatternSyntaxException e) {
            throw new IllegalArgumentException("正则表达式无效：" + e.getMessage());
        }
        Path base = resolveProject(project);
        StringBuilder sb = new StringBuilder();
        final int[] hits = {0};
        final boolean[] overflow = {false};
        Files.walk(base).filter(Files::isRegularFile).forEach(p -> {
            if (hits[0] >= MAX_SEARCH_HITS || overflow[0]) return;
            String rel = base.relativize(p).toString().replace('\\', '/');
            if (!isTextFile(rel)) return;
            try {
                String content = new String(Files.readAllBytes(p), StandardCharsets.UTF_8);
                String[] lines = content.split("\r?\n", -1);
                for (int i = 0; i < lines.length; i++) {
                    if (pattern.matcher(lines[i]).find()) {
                        if (hits[0] >= MAX_SEARCH_HITS) { overflow[0] = true; break; }
                        String line = lines[i].trim();
                        sb.append(rel).append(":").append(i + 1).append(": ").append(truncate(line, 200)).append("\n");
                        hits[0]++;
                    }
                }
            } catch (Exception ignored) {}
        });
        if (sb.length() == 0) return "未找到匹配 \"" + keyword + "\" 的内容";
        String header = "搜索 \"" + keyword + "\" 命中 " + hits[0] + " 处" + (overflow[0] ? "（已达上限，可能还有更多）" : "") + "：\n";
        return header + sb;
    }

    // ---------- 工具6：查询默认wxapkg路径 ----------

    private String toolDefaultPath() {
        String pathStr = getConfiguredWxapkgPath();
        StringBuilder sb = new StringBuilder();
        sb.append("默认打开路径：").append(pathStr).append("\n");
        Path dir = Paths.get(pathStr);
        if (!Files.isDirectory(dir)) {
            sb.append("目录状态：不存在或不可访问\n");
            return sb.toString();
        }
        sb.append("目录状态：正常\n");
        sb.append("一级文件夹数：").append(countSubDirs(dir)).append("\n");
        List<File> wxapkgs = new ArrayList<>();
        scanWxapkgRecursive(dir.toFile(), wxapkgs);
        sb.append("wxapkg文件数：").append(wxapkgs.size()).append("\n");
        return sb.toString();
    }

    /** 读取插件配置的默认wxapkg路径，未配置时用内置默认值 */
    private String getConfiguredWxapkgPath() {
        try {
            Config.SavedConfig cfg = Config.loadConfigFile();
            String path = cfg.getwxapkgPath();
            if (path != null && !path.trim().isEmpty()) return path.trim();
        } catch (Exception ignored) {
        }
        return Config.DEFAULT_WXAPKGPATH;
    }

    // ---------- 工具7：列出目录下所有文件夹信息 ----------

    private String toolListFolders(JsonNode args) throws IOException {
        String pathStr = args.path("path").asText("").trim();
        if (pathStr.isEmpty()) pathStr = getConfiguredWxapkgPath();
        Path base = Paths.get(pathStr).toAbsolutePath().normalize();
        if (!Files.isDirectory(base)) throw new IllegalArgumentException("目录不存在：" + base);

        List<Path> dirs = new ArrayList<>();
        try (java.util.stream.Stream<Path> stream = Files.list(base)) {
            stream.filter(Files::isDirectory).forEach(dirs::add);
        }
        dirs.sort(Comparator.comparing((Path p) -> p.getFileName().toString().toLowerCase()));

        StringBuilder sb = new StringBuilder();
        sb.append("目录：").append(base).append("\n");
        sb.append("共 ").append(dirs.size()).append(" 个一级文件夹：\n");
        int index = 1;
        for (Path dir : dirs) {
            if (index > MAX_LIST_ITEMS) {
                sb.append("... 其余 ").append(dirs.size() - MAX_LIST_ITEMS).append(" 个已省略\n");
                break;
            }
            BasicFileAttributes attrs = Files.readAttributes(dir, BasicFileAttributes.class);
            List<File> wxapkgs = new ArrayList<>();
            scanWxapkgRecursive(dir.toFile(), wxapkgs);
            sb.append("[").append(index++).append("] ").append(dir.getFileName()).append("\n");
            sb.append("    创建时间：").append(formatTime(attrs.creationTime())).append("\n");
            sb.append("    修改时间：").append(formatTime(attrs.lastModifiedTime())).append("\n");
            sb.append("    文件总数：").append(countFiles(dir.toFile())).append("\n");
            sb.append("    wxapkg数：").append(wxapkgs.size()).append("\n");
        }
        return sb.toString();
    }

    private int countSubDirs(Path dir) {
        try (java.util.stream.Stream<Path> stream = Files.list(dir)) {
            return (int) stream.filter(Files::isDirectory).count();
        } catch (IOException e) {
            return 0;
        }
    }

    private String formatTime(FileTime time) {
        if (time == null) return "-";
        return DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
                .withZone(ZoneId.systemDefault())
                .format(time.toInstant());
    }

    // ---------- 工具8：提取API接口列表 ----------

    private String toolApiList(JsonNode args) throws IOException {
        String project = args.path("project").asText("").trim();
        if (project.isEmpty()) throw new IllegalArgumentException("缺少参数：project");
        int maxItems = args.has("max_items") ? args.path("max_items").asInt(300) : 300;
        if (maxItems <= 0) maxItems = 300;

        // 使用插件配置里的API正则，未配置时用默认正则
        Pattern configuredPattern = Config.DEFAULT_API_PATTERN;
        try {
            Config.SavedConfig cfg = Config.loadConfigFile();
            configuredPattern = compileOr(cfg.getApiRegex(), Config.DEFAULT_API_PATTERN);
        } catch (Exception ignored) {
        }
        final Pattern apiPattern = configuredPattern;

        Path base = resolveProject(project);
        Map<String, ApiStat> stats = new HashMap<>();
        Files.walk(base).filter(Files::isRegularFile).forEach(p -> {
            String rel = base.relativize(p).toString().replace('\\', '/');
            if (!isTextFile(rel)) return;
            try {
                String content = new String(Files.readAllBytes(p), StandardCharsets.UTF_8);
                String[] lines = content.split("\r?\n", -1);
                for (int i = 0; i < lines.length; i++) {
                    Matcher matcher = apiPattern.matcher(lines[i]);
                    while (matcher.find()) {
                        String url = null;
                        for (int g = 1; g <= matcher.groupCount(); g++) {
                            String value = matcher.group(g);
                            if (value != null && !value.trim().isEmpty()) {
                                url = value.trim();
                                break;
                            }
                        }
                        if (url == null || url.isEmpty()) continue;
                        String location = rel + ":" + (i + 1);
                        stats.computeIfAbsent(url, k -> new ApiStat(location)).count++;
                    }
                }
            } catch (Exception ignored) {
            }
        });
        if (stats.isEmpty()) return "未提取到API接口（项目：" + base.getFileName() + "）";

        List<Map.Entry<String, ApiStat>> list = new ArrayList<>(stats.entrySet());
        list.sort((a, b) -> b.getValue().count != a.getValue().count
                ? Integer.compare(b.getValue().count, a.getValue().count)
                : a.getKey().compareTo(b.getKey()));

        StringBuilder sb = new StringBuilder();
        sb.append("项目：").append(base.getFileName()).append("\n");
        sb.append("API接口数：").append(list.size()).append("\n");
        int index = 1;
        for (Map.Entry<String, ApiStat> e : list) {
            if (index > maxItems) {
                sb.append("... 其余 ").append(list.size() - maxItems).append(" 个已省略\n");
                break;
            }
            sb.append("[").append(index++).append("] ").append(e.getKey())
                    .append("  (").append(e.getValue().count).append("次, 首次: ")
                    .append(e.getValue().firstSeen).append(")\n");
        }
        return sb.toString();
    }

    /** API命中统计 */
    private static class ApiStat {
        int count = 0;
        final String firstSeen;

        ApiStat(String firstSeen) {
            this.firstSeen = firstSeen;
        }
    }

    // ---------- 工具9：按域名提取接口及参数示例 ----------

    private String toolDomainApiParams(JsonNode args) throws IOException {
        String domain = args.path("domain").asText("").trim();
        if (domain.isEmpty()) throw new IllegalArgumentException("缺少参数：domain");
        String project = args.path("project").asText("").trim();
        int maxItems = args.has("max_items") ? args.path("max_items").asInt(50) : 50;
        if (maxItems <= 0) maxItems = 50;

        domain = domain.replaceFirst("(?i)^https?://", "");
        int slash = domain.indexOf('/');
        if (slash >= 0) domain = domain.substring(0, slash);
        String domainLower = domain.toLowerCase();

        // 未指定项目时扫描所有已反编译项目
        List<Path> bases = new ArrayList<>();
        if (!project.isEmpty()) {
            bases.add(resolveProject(project));
        } else {
            Path root = Paths.get(OUTPUT_DIR);
            if (Files.isDirectory(root)) {
                try (DirectoryStream<Path> ds = Files.newDirectoryStream(root)) {
                    for (Path p : ds) if (Files.isDirectory(p)) bases.add(p);
                }
            }
        }
        if (bases.isEmpty()) return "没有可扫描的反编译项目（输出目录：" + OUTPUT_DIR + "）";

        Map<String, DomainApi> apis = new LinkedHashMap<>();
        Map<String, String> cryptoProfiles = new LinkedHashMap<>();
        for (Path base : bases) {
            // 先找该项目的接口前缀（siteroot），用于还原“siteroot + 相对路径”的接口
            String siteRoot = findSiteRoot(base, domainLower);
            String siteRootKey = normalizeBaseUrl(siteRoot);
            String crypto = detectCrypto(base);
            cryptoProfiles.put(base.getFileName().toString(), crypto);

            Files.walk(base).filter(Files::isRegularFile).forEach(p -> {
                String rel = base.relativize(p).toString().replace('\\', '/');
                if (!isTextFile(rel)) return;
                try {
                    String content = new String(Files.readAllBytes(p), StandardCharsets.UTF_8);
                    String fileKey = base.getFileName() + "/" + rel;

                    // 1) 绝对URL
                    Matcher um = HTTP_URL_PATTERN.matcher(content);
                    while (um.find()) {
                        String url = trimUrlTail(um.group());
                        if (!url.toLowerCase().contains(domainLower)) continue;
                        String endpoint = stripQuery(url);
                        if (isBaseUrl(endpoint, siteRootKey)) continue;
                        recordApi(apis, endpoint, url, content, um.start(), um.end(),
                                fileKey + ":" + lineOf(content, um.start()), crypto);
                    }

                    // 2) siteroot + 相对路径，例如 request({url:"jx_appid/search"})
                    if (siteRoot != null) {
                        Matcher rm = RELATIVE_URL_PATTERN.matcher(content);
                        while (rm.find()) {
                            String path = rm.group(1).trim();
                            if (!isApiPath(path)) continue;
                            int beforeFrom = Math.max(0, rm.start() - 300);
                            if (!REQUEST_CALL_PATTERN.matcher(content.substring(beforeFrom, rm.start())).find()) continue;
                            String fullUrl = joinUrl(siteRoot, path);
                            String endpoint = stripQuery(fullUrl);
                            if (isBaseUrl(endpoint, siteRootKey)) continue;
                            recordApi(apis, endpoint, fullUrl, content, rm.start(), rm.end(),
                                    fileKey + ":" + lineOf(content, rm.start()), crypto);
                        }
                    }
                } catch (Exception ignored) {
                }
            });
        }

        if (apis.isEmpty()) return "未找到域名 " + domain + " 的接口（已扫描 " + bases.size() + " 个项目）";

        List<DomainApi> list = new ArrayList<>(apis.values());
        list.sort((a, b) -> b.count != a.count
                ? Integer.compare(b.count, a.count)
                : a.endpoint.compareTo(b.endpoint));

        StringBuilder sb = new StringBuilder();
        sb.append("域名：").append(domain).append("\n");
        sb.append("扫描项目数：").append(bases.size()).append("\n");
        sb.append("接口数：").append(list.size()).append("\n");
        for (Map.Entry<String, String> e : cryptoProfiles.entrySet()) {
            sb.append("加密检测: ").append(e.getKey()).append(" = ").append(e.getValue()).append("\n");
        }
        sb.append("\n");

        int index = 1;
        for (DomainApi api : list) {
            if (index > maxItems) {
                sb.append("... 其余 ").append(list.size() - maxItems).append(" 个接口已省略\n");
                break;
            }
            sb.append("[").append(index++).append("] ").append(api.endpoint).append("\n");
            sb.append("    Method: ").append(api.methods.isEmpty() ? "未识别" : String.join("/", api.methods)).append("\n");
            if (!api.paramKeys.isEmpty()) sb.append("    参数键: ").append(String.join(", ", api.paramKeys)).append("\n");
            if (!api.sampleParams.isEmpty()) sb.append("    示例参数: ").append(toJsonLike(api.sampleParams)).append("\n");
            if (!api.headerKeys.isEmpty()) sb.append("    请求头键: ").append(String.join(", ", api.headerKeys)).append("\n");
            if (!api.crypto.isEmpty()) sb.append("    加密: ").append(api.crypto).append("\n");
            if (!api.chains.isEmpty()) sb.append("    调用链: ").append(String.join(" | ", api.chains)).append("\n");
            sb.append("    出现次数: ").append(api.count).append("，首次: ").append(api.firstSeen).append("\n");
            for (String snippet : api.snippets) sb.append("    源码片段: ").append(snippet).append("\n");
            sb.append("\n");
        }
        return sb.toString();
    }

    private static final Pattern HTTP_URL_PATTERN = Pattern.compile("https?://[^\\s\"'`<>()\\\\]+");
    private static final Pattern METHOD_PATTERN = Pattern.compile("method\\s*:\\s*[\"'](GET|POST|PUT|DELETE|PATCH|HEAD)[\"']", Pattern.CASE_INSENSITIVE);
    private static final Pattern PARAM_BLOCK_PATTERN = Pattern.compile("(?:data|params|payload|body|query)\\s*:\\s*\\{");
    private static final Pattern HEADER_BLOCK_PATTERN = Pattern.compile("headers?\\s*:\\s*\\{");
    private static final Pattern QUOTED_KEY_PATTERN = Pattern.compile("[\"']([A-Za-z0-9_\\-]+)[\"']\\s*:");
    private static final Pattern PARAM_KV_PATTERN = Pattern.compile(
            "[\"']?([A-Za-z_$][\\w$]*)[\"']?\\s*:\\s*(?:\"([^\"]*)\"|'([^']*)'|(-?\\d+(?:\\.\\d+)?)|(true|false)|[A-Za-z_$][\\w$]*(?:\\.[\\w$]+|\\[[^\\]]*\\])*)");
    private static final Pattern SITEROOT_PATTERN = Pattern.compile("siteroot\\s*:\\s*[\"']([^\"']+)[\"']");
    private static final Pattern RELATIVE_URL_PATTERN = Pattern.compile("url\\s*:\\s*[\"']([^\"']+)[\"']");
    private static final Pattern REQUEST_CALL_PATTERN = Pattern.compile("(?:request|ajax|fetch)\\s*\\(", Pattern.CASE_INSENSITIVE);
    private static final Pattern STATIC_PATH_PATTERN = Pattern.compile(
            "(?i)\\.(js|json|wxml|wxss|css|html?|png|jpe?g|gif|svg|webp|mp3|mp4|ttf|woff2?|astc|wasm)$");
    private static final Pattern WX_ROUTE_PATTERN = Pattern.compile("__wxRoute\\s*=\\s*[\"']([^\"']+)[\"']");
    private static final Pattern WX_FILE_PATTERN = Pattern.compile("__wxAppCurrentFile__\\s*=\\s*[\"']([^\"']+)[\"']");
    private static final Pattern DEFINE_FILE_PATTERN = Pattern.compile("define\\(\\s*[\"']([^\"']+\\.js)[\"']");
    private static final Pattern HANDLER_PATTERN = Pattern.compile("([A-Za-z_$][\\w$]*)\\s*:\\s*function\\s*\\(");
    private static final Pattern PASS_PHRASE_PATTERN = Pattern.compile(
            "AES\\.encrypt\\([^,]{1,200},\\s*[\"']([^\"']{1,64})[\"']");
    private static final Set<String> CALLBACK_NAMES = new java.util.HashSet<>(java.util.Arrays.asList(
            "success", "fail", "complete", "then", "catch", "callback", "resolve", "reject",
            "done", "next", "error", "finally", "forEach", "map", "filter", "reduce"));

    /** 取从 '{' 开始的一段花括号内容（最多 800 字符） */
    private static String braceBlock(String content, int braceIndex) {
        int depth = 0;
        int limit = Math.min(content.length(), braceIndex + 800);
        for (int i = braceIndex; i < limit; i++) {
            char c = content.charAt(i);
            if (c == '{') depth++;
            else if (c == '}') {
                depth--;
                if (depth == 0) return content.substring(braceIndex, i + 1);
            }
        }
        return content.substring(braceIndex, limit);
    }

    /** 从参数对象里提取键与字面量示例值 */
    private static void collectParamKeys(String block, DomainApi api) {
        Matcher kv = PARAM_KV_PATTERN.matcher(block);
        while (kv.find()) {
            String key = kv.group(1);
            if ("function".equals(key) || "return".equals(key) || "if".equals(key)) continue;
            api.paramKeys.add(key);
            if (!api.sampleParams.containsKey(key)) {
                String value = kv.group(2) != null ? kv.group(2)
                        : kv.group(3) != null ? kv.group(3)
                        : kv.group(4) != null ? kv.group(4) : kv.group(5);
                if (value != null) api.sampleParams.put(key, value);
            }
        }
    }

    private static String toJsonLike(Map<String, String> map) {
        StringBuilder sb = new StringBuilder("{");
        int i = 0;
        for (Map.Entry<String, String> e : map.entrySet()) {
            if (i++ > 0) sb.append(", ");
            sb.append('"').append(e.getKey()).append("\": ");
            if (e.getValue().matches("(?i)true|false|-?\\d+(\\.\\d+)?")) sb.append(e.getValue());
            else sb.append('"').append(e.getValue().replace("\"", "\\\"")).append('"');
        }
        return sb.append('}').toString();
    }

    private static String trimUrlTail(String s) {
        int end = s.length();
        while (end > 0 && ",;)]}'\"`".indexOf(s.charAt(end - 1)) >= 0) end--;
        return s.substring(0, end);
    }

    private static int lineOf(String content, int index) {
        int line = 1;
        int limit = Math.min(index, content.length());
        for (int i = 0; i < limit; i++) if (content.charAt(i) == '\n') line++;
        return line;
    }

    /** 记录一次接口命中：方法、参数键、示例值、请求头键、源码片段 */
    private void recordApi(Map<String, DomainApi> apis, String endpoint, String fullUrl,
                           String content, int start, int end, String location, String crypto) {
        DomainApi api = apis.get(endpoint);
        if (api == null) {
            api = new DomainApi(endpoint, location);
            apis.put(endpoint, api);
        }
        api.count++;
        if (api.crypto.isEmpty() && crypto != null && !crypto.isEmpty()) api.crypto = crypto;

        // 页面/组件 + 方法名，构成调用链
        if (api.chains.size() < 2) {
            String chain = buildChain(content, start);
            if (chain != null) api.chains.add(chain);
        }

        int from = Math.max(0, start - 600);
        int to = Math.min(content.length(), end + 600);
        String ctx = content.substring(from, to);
        int relIndex = start - from;
        // 参数/方法/请求头通常在 URL 之后，用较窄的窗口减少相邻请求的干扰
        String near = content.substring(Math.max(0, start - 120), Math.min(content.length(), start + 400));

        // 请求方法
        Matcher mm = METHOD_PATTERN.matcher(near);
        if (mm.find()) api.methods.add(mm.group(1).toUpperCase());

        // URL 自带 query 参数
        int q = fullUrl.indexOf('?');
        if (q >= 0) {
            String query = fullUrl.substring(q + 1);
            int hash = query.indexOf('#');
            if (hash >= 0) query = query.substring(0, hash);
            for (String pair : query.split("&")) {
                String key = pair.split("=", 2)[0].trim();
                if (key.matches("[A-Za-z_$][\\w$.\\[\\]]*")) api.paramKeys.add(key);
            }
        }

        // 附近的 data / params / body 对象
        Matcher pm = PARAM_BLOCK_PATTERN.matcher(near);
        while (pm.find()) collectParamKeys(braceBlock(near, pm.end() - 1), api);

        // 附近的 header 对象
        Matcher hm = HEADER_BLOCK_PATTERN.matcher(near);
        while (hm.find()) {
            Matcher hk = QUOTED_KEY_PATTERN.matcher(braceBlock(near, hm.end() - 1));
            while (hk.find()) api.headerKeys.add(hk.group(1));
        }

        // 以 URL 为中心的源码片段
        if (api.snippets.size() < 2) {
            int s = Math.max(0, relIndex - 120);
            int e = Math.min(ctx.length(), relIndex + 120);
            String snippet = truncate(ctx.substring(s, e).replaceAll("\\s+", " ").trim(), 240);
            if (!api.snippets.contains(snippet)) api.snippets.add(snippet);
        }
    }

    /** 在项目中查找包含目标域名的接口前缀 siteroot */
    private String findSiteRoot(Path base, String domainLower) {
        final String[] root = {null};
        try {
            Files.walk(base).filter(Files::isRegularFile).forEach(p -> {
                if (root[0] != null) return;
                String rel = base.relativize(p).toString().replace('\\', '/');
                if (!isTextFile(rel)) return;
                try {
                    String content = new String(Files.readAllBytes(p), StandardCharsets.UTF_8);
                    Matcher m = SITEROOT_PATTERN.matcher(content);
                    while (m.find()) {
                        String value = m.group(1);
                        if (value.toLowerCase().contains(domainLower)) {
                            root[0] = value;
                            return;
                        }
                    }
                } catch (Exception ignored) {
                }
            });
        } catch (IOException ignored) {
        }
        return root[0];
    }

    private static String stripQuery(String url) {
        int q = url.indexOf('?');
        if (q >= 0) url = url.substring(0, q);
        int h = url.indexOf('#');
        if (h >= 0) url = url.substring(0, h);
        return url;
    }

    private static String normalizeBaseUrl(String url) {
        if (url == null) return null;
        String u = url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
        return u.toLowerCase();
    }

    private static boolean isBaseUrl(String endpoint, String siteRootKey) {
        String key = normalizeBaseUrl(endpoint);
        if (siteRootKey != null && siteRootKey.equals(key)) return true;
        return key.matches("https?://[^/]+");
    }

    private static boolean isApiPath(String path) {
        if (path.isEmpty() || path.length() > 300) return false;
        String lower = path.toLowerCase();
        if (lower.startsWith("http") || lower.startsWith("//") || lower.startsWith("wxfile")
                || lower.startsWith("plugin://") || lower.startsWith("data:")) return false;
        if (STATIC_PATH_PATTERN.matcher(lower).find()) return false;
        return !lower.contains("pages/") && !lower.contains("components/");
    }

    private static String joinUrl(String base, String path) {
        String b = base.endsWith("/") ? base.substring(0, base.length() - 1) : base;
        return path.startsWith("/") ? b + path : b + "/" + path;
    }

    /** 页面/组件路由 + 调用方法，构成“pages/xxx > method”调用链 */
    private static String buildChain(String content, int start) {
        String page = null;
        Matcher rm = WX_ROUTE_PATTERN.matcher(content);
        while (rm.find() && rm.start() < start) page = rm.group(1);
        if (page == null) {
            Matcher fm = WX_FILE_PATTERN.matcher(content);
            while (fm.find() && fm.start() < start) page = fm.group(1);
        }
        if (page == null) {
            Matcher dm = DEFINE_FILE_PATTERN.matcher(content);
            while (dm.find() && dm.start() < start) page = dm.group(1);
        }

        String handler = null;
        int from = Math.max(0, start - 8000);
        Matcher hm = HANDLER_PATTERN.matcher(content);
        hm.region(from, start);
        while (hm.find()) {
            String name = hm.group(1);
            if (CALLBACK_NAMES.contains(name)) continue;
            handler = name;
        }
        if (page == null && handler == null) return null;
        if (page == null) return handler;
        return handler == null ? page : page + " > " + handler;
    }

    /** 检测项目使用的加密方式（基于代码特征，非运行时） */
    private String detectCrypto(Path base) {
        final boolean[] wxKey = {false};
        final boolean[] aes = {false};
        final boolean[] rsa = {false};
        final boolean[] sm = {false};
        final String[] passPhrase = {null};

        try {
            Files.walk(base).filter(Files::isRegularFile).forEach(p -> {
                String rel = base.relativize(p).toString().replace('\\', '/');
                if (!isTextFile(rel)) return;
                try {
                    if (Files.size(p) > 20L * 1024 * 1024) return;
                    String content = new String(Files.readAllBytes(p), StandardCharsets.UTF_8);
                    if (content.contains("getUserCryptoManager")) wxKey[0] = true;
                    if (content.contains("AES.encrypt") || content.contains("CryptoJS.AES")
                            || content.contains("crypto-js")) aes[0] = true;
                    if (content.contains("JSEncrypt") || content.contains("RSA")) rsa[0] = true;
                    String lower = content.toLowerCase();
                    if (lower.contains("sm2") || lower.contains("sm4")) sm[0] = true;
                    if (passPhrase[0] == null) {
                        Matcher m = PASS_PHRASE_PATTERN.matcher(content);
                        if (m.find()) passPhrase[0] = m.group(1);
                    }
                } catch (Exception ignored) {
                }
            });
        } catch (IOException ignored) {
        }

        List<String> parts = new ArrayList<>();
        if (wxKey[0] && aes[0]) parts.add("AES-CBC(微信用户密钥encryptKey/iv, Base64)");
        else if (aes[0]) parts.add("AES(CryptoJS)");
        if (rsa[0]) parts.add("RSA");
        if (sm[0]) parts.add("SM2/SM4");
        if (passPhrase[0] != null) parts.add("硬编码口令:" + passPhrase[0]);
        return parts.isEmpty() ? "未检测到加密" : String.join(", ", parts);
    }

    /** 域名接口聚合信息 */
    private static class DomainApi {
        final String endpoint;
        final String firstSeen;
        final Set<String> methods = new LinkedHashSet<>();
        final Set<String> paramKeys = new LinkedHashSet<>();
        final Set<String> headerKeys = new LinkedHashSet<>();
        final Map<String, String> sampleParams = new LinkedHashMap<>();
        final List<String> snippets = new ArrayList<>();
        final Set<String> chains = new LinkedHashSet<>();
        String crypto = "";
        int count;

        DomainApi(String endpoint, String firstSeen) {
            this.endpoint = endpoint;
            this.firstSeen = firstSeen;
        }
    }

    // ==================== 工具方法 ====================

    /** 解析项目路径：优先按appid在输出目录下找，其次允许绝对路径 */
    private Path resolveProject(String project) throws IOException {
        Path base = Paths.get(OUTPUT_DIR, project).normalize();
        if (Files.isDirectory(base)) return base;
        Path abs = Paths.get(project).toAbsolutePath().normalize();
        if (Files.isDirectory(abs)) return abs;
        throw new IllegalArgumentException("项目不存在：" + project + "（先执行 decompile_wxapkg 或使用 list_decompiled_projects 查看）");
    }

    /** 防目录穿越的文件解析 */
    private Path safeResolve(Path base, String rel) throws IOException {
        Path target = base.resolve(rel).normalize();
        if (!target.startsWith(base)) throw new IllegalArgumentException("非法路径：" + rel);
        return target;
    }

    private void scanWxapkgRecursive(File dir, List<File> out) {
        File[] files = dir.listFiles();
        if (files == null) return;
        for (File f : files) {
            if (f.isDirectory()) scanWxapkgRecursive(f, out);
            else if (f.getName().toLowerCase().endsWith(".wxapkg")) out.add(f);
        }
    }

    private long countFiles(File dir) {
        long n = 0;
        File[] files = dir.listFiles();
        if (files == null) return 0;
        for (File f : files) {
            if (f.isDirectory()) n += countFiles(f);
            else n++;
        }
        return n;
    }

    private boolean isTextFile(String relPath) {
        int dot = relPath.lastIndexOf('.');
        if (dot == -1) return false;
        return TEXT_EXTS.contains(relPath.substring(dot + 1).toLowerCase());
    }

    private List<WxAppletDecompiler.ApiInfo> dedupApis(List<WxAppletDecompiler.ApiInfo> list) {
        Map<String, WxAppletDecompiler.ApiInfo> map = new LinkedHashMap<>();
        for (WxAppletDecompiler.ApiInfo info : list) map.putIfAbsent(info.getApi(), info);
        List<WxAppletDecompiler.ApiInfo> sorted = new ArrayList<>(map.values());
        sorted.sort(Comparator.comparing(WxAppletDecompiler.ApiInfo::getApi));
        return sorted;
    }

    private Pattern compileOr(String regex, Pattern defaultPattern) {
        if (regex == null || regex.trim().isEmpty()) return defaultPattern;
        try {
            return Pattern.compile(regex);
        } catch (PatternSyntaxException e) {
            return defaultPattern;
        }
    }

    private Map<String, Pattern> buildSensitivePatterns(Config.SavedConfig cfg) {
        Map<String, Pattern> result = new HashMap<>();
        Map<String, String> map = cfg.getSensitiveRegexMap();
        if (map == null || map.isEmpty()) {
            // 空配置时用默认敏感规则
            map = Config.parseSensitiveTextToMap("");
        }
        for (Map.Entry<String, String> e : map.entrySet()) {
            try {
                result.put(e.getKey(), Pattern.compile(e.getValue()));
            } catch (PatternSyntaxException ignored) {}
        }
        if (result.isEmpty()) {
            for (Map.Entry<String, Pattern> e : Config.DEFAULT_SENSITIVE_PATTERNS.entrySet()) {
                result.put(e.getKey(), e.getValue());
            }
        }
        return result;
    }

    private String truncate(String text, int maxChars) {
        if (text == null) return "";
        if (text.length() <= maxChars) return text;
        return text.substring(0, maxChars) + "\n...[内容过长，已截断，共 " + text.length() + " 字符]";
    }

    /** SSE会话 */
    private static class SseSession {
        final String id;
        final HttpExchange exchange;
        final OutputStream out;
        volatile boolean closed = false;
        SseSession(String id, HttpExchange exchange, OutputStream out) {
            this.id = id;
            this.exchange = exchange;
            this.out = out;
        }
        void close() {
            closed = true;
            try { exchange.close(); } catch (Exception ignored) {}
        }

        /** 通过 SSE 通道推送一条 JSON-RPC 消息 */
        synchronized void send(String json) {
            if (closed) return;
            try {
                out.write(("event: message\ndata: " + json + "\n\n").getBytes(StandardCharsets.UTF_8));
                out.flush();
            } catch (Exception e) {
                closed = true;
            }
        }

        /** 心跳，防止连接被中间层断开 */
        synchronized void keepAlive() {
            if (closed) return;
            try {
                out.write(": keep-alive\n\n".getBytes(StandardCharsets.UTF_8));
                out.flush();
            } catch (Exception e) {
                closed = true;
            }
        }
    }
}
