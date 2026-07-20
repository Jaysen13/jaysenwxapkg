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
import okhttp3.*;
import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.*;
import java.util.concurrent.*;
import java.util.regex.Pattern;

/**
 * 微信小程序反编译 + 信息泄露检测
 */
public class WxAppletDecompiler {
    // ========== 基础配置（外部传入） ==========
    private String wxapkgFilePath;
    private String outputDir;
    private int threadNum;
    // 自定义配置
    private Pattern customApiPattern;       // 自定义API提取正则
    private Map<String, Pattern> customSensitivePatterns; // 自定义敏感信息正则
    private Set<String> suffixBlacklist;    // URL后缀黑名单（仅用于URL过滤）
    private Set<String> prefixBlacklist; // 接口前缀过滤黑名单

    // ========== 结构化结果容器 ==========
    private final List<AppInfo> appInfoList = new ArrayList<>();
    private final List<ApiInfo> apiInfoList = new ArrayList<>();
    private final List<SensitiveInfo> sensitiveInfoList = new ArrayList<>();
    private final StringBuilder errorBuilder = new StringBuilder();
    private int apiIndex = 1;

    // 全局工具
    private final OkHttpClient okHttpClient = new OkHttpClient.Builder()
            .connectTimeout(5, TimeUnit.SECONDS)
            .readTimeout(5, TimeUnit.SECONDS)
            .build();
    private final ObjectMapper objectMapper = new ObjectMapper();
    // AES解密工具实例
    private final WxapkgAesDe aesDecompiler = new WxapkgAesDe();
    // 默认正则
    private static final Pattern DEFAULT_API_PATTERN = Config.DEFAULT_API_PATTERN;
    // 默认敏感信息正则
    private static final Map<String, Pattern> DEFAULT_SENSITIVE_PATTERNS = Config.DEFAULT_SENSITIVE_PATTERNS;
    // 默认URL后缀黑名单（仅用于过滤无参数的无用URL）
    public static Set<String> DEFAULT_SUFFIX_BLACKLIST = Config.DEFAULT_SUFFIX_BLACKLIST;

    // ========== 构造函数（初始化URL后缀黑名单） ==========
    public WxAppletDecompiler(String wxapkgFilePath, String outputDir, int threadNum,
                              Pattern customApiPattern, Map<String, Pattern> customSensitivePatterns, Set<String> suffixBlacklist, Set<String> prefixBlacklist) {
        this.wxapkgFilePath = wxapkgFilePath;
        this.outputDir = outputDir;
        this.threadNum = threadNum;

        // 初始化正则配置
        this.customApiPattern = customApiPattern != null ? customApiPattern : DEFAULT_API_PATTERN;
        this.customSensitivePatterns = customSensitivePatterns != null && !customSensitivePatterns.isEmpty()
                ? customSensitivePatterns : DEFAULT_SENSITIVE_PATTERNS;

        // 初始化URL后缀黑名单（用户自定义/默认）
        this.suffixBlacklist = new HashSet<>();
        if (suffixBlacklist != null && !suffixBlacklist.isEmpty()) {
            this.suffixBlacklist.addAll(suffixBlacklist); // 用户自定义完全生效
        } else {
            this.suffixBlacklist.addAll(DEFAULT_SUFFIX_BLACKLIST); // 无自定义则用默认
        }
        // 初始化接口前缀过滤黑名单
        this.prefixBlacklist = new HashSet<>();
        if (prefixBlacklist != null && !prefixBlacklist.isEmpty()) {
            this.prefixBlacklist.addAll(prefixBlacklist);
        } else {
            this.prefixBlacklist.addAll(Config.DEFAULT_PREFIX_BLACKLIST);
        }
    }

    /**
     * 核心执行函数
     */
    public void execute() {
        // 1. 校验文件
        File wxapkgFile = new File(wxapkgFilePath);
        if (!wxapkgFile.exists() || !wxapkgFile.isFile()) {
            errorBuilder.append("❌ 错误：指定的wxapkg文件不存在！路径：").append(wxapkgFilePath);
            addAppInfo("错误信息", errorBuilder.toString());
            return;
        }

        // 2. 提取AppID
        String appID = extractWxId();
        if (appID.equals("unknown")) {
            addAppInfo("AppID", "未提取到（使用默认：unknown_appid）");
            appID = "unknown_appid";
        } else {
            addAppInfo("AppID", appID);
        }

        // 3. 创建输出目录（默认=C:\Users\${USER}\.burp）
        String finalOutputDir = outputDir + File.separator + appID;
        Path outputPath = Paths.get(outputDir);
        try {
            Files.createDirectories(outputPath);
            addAppInfo("解包输出目录", finalOutputDir);
        } catch (IOException e) {
            errorBuilder.append("❌ 创建输出目录失败：").append(e.getMessage());
            addAppInfo("错误信息", errorBuilder.toString());
            return;
        }

        //  尝试直接执行解包
        addAppInfo("解包状态", "开始解包wxapkg文件：" + wxapkgFilePath);
        int fileCount = unpack(wxapkgFilePath, finalOutputDir, threadNum);
        if (fileCount == 0) {
            addAppInfo("解包状态", "❌ 直接解包失败，尝试AES解密后重试...");
            try {
                // 校验是否为加密的wxapkg
                if (!aesDecompiler.isEncryptedWxapkg(wxapkgFilePath)) {
                    addAppInfo("解包状态", "❌ 非加密wxapkg包，解包失败！");
                    return;
                }
                // 生成临时解密文件
                File srcFile = new File(wxapkgFilePath);
                String tempFileName = srcFile.getName().replace(".wxapkg", "") + "_jaysentmp.wxapkg";
                String tempDecryptedFile = new File(finalOutputDir, tempFileName).getAbsolutePath();
                // 执行AES解密（使用提取的AppID作为wxid）
                aesDecompiler.decrypt(appID, wxapkgFilePath, tempDecryptedFile);
                addAppInfo("AES解密", "✅ 加密包解密成功：" + tempDecryptedFile);

                // 用解密后的文件重新解包
                fileCount = unpack(tempDecryptedFile, finalOutputDir, threadNum);
                if (fileCount == 0) {
                    addAppInfo("解包状态", "❌ AES解密后解包仍失败！");
                    return;
                }
                addAppInfo("解包结果", "✅ AES解密后解包完成！共解压 " + fileCount + " 个文件");
            } catch (Exception e) {
                addAppInfo("AES解密失败", "❌ " + e.getMessage());
                return;
            }
        } else {
            addAppInfo("解包结果", "✅ 直接解包完成！共解压 " + fileCount + " 个文件");
        }

        // 查询小程序信息
        Map<String, String> wxapkgInfo = queryAppInfo(appID);
        addAppInfo("小程序名称", wxapkgInfo.get("nickName"));
        addAppInfo("用户名", wxapkgInfo.get("userName"));
        addAppInfo("描述", wxapkgInfo.get("description"));
        addAppInfo("主体名称", wxapkgInfo.get("principalName"));

        // 信息泄露检测（不过滤文件，仅过滤URL）
        addAppInfo("检测状态", "🔍 开始执行信息泄露检测（所有文件都扫描）...");
        infoLeakDetect(finalOutputDir);
        addAppInfo("检测状态", "✅ 信息泄露检测完成！");
    }

    /**
     * 解包wxapkg文件
     */
    public int unpack(String wxapkgPath, String outputPath, int threadNum) {
        File wxapkgFile = new File(wxapkgPath);
        byte[] decryptedData;
        try {
            decryptedData = Files.readAllBytes(wxapkgFile.toPath());
        } catch (IOException e) {
//            addAppInfo("错误信息", "❌ 读取wxapkg文件失败：" + e.getMessage());
            return 0;
        }
        if (decryptedData.length < 14 || decryptedData[0] != (byte) 0xBE || decryptedData[13] != (byte) 0xED) {
//            addAppInfo("错误信息", "❌ 解包失败：文件不是可用的wxapkg文件（头标记不匹配）");
            return 0;
        }
        long fileCount = readUnit(Arrays.copyOfRange(decryptedData, 14, 18));
        if (fileCount <= 0 || fileCount > Integer.MAX_VALUE) {
//            addAppInfo("错误信息", "❌ 解包失败：文件数量异常");
            return 0;
        }
        List<FileMeta> fileList = new ArrayList<>();
        int idx = 18;
        for (int i = 0; i < fileCount; i++) {
            byte[] nameLenByte = Arrays.copyOfRange(decryptedData, idx, idx + 4);
            idx += 4;
            long nameLen = readUnit(nameLenByte);
            if (nameLen > 10485760) {
//                addAppInfo("错误信息", "❌ 解包失败：文件名长度异常");
                return 0;
            }
            byte[] nameBytes = Arrays.copyOfRange(decryptedData, idx, idx + (int) nameLen);
            idx += (int) nameLen;
            String name = new String(nameBytes, StandardCharsets.UTF_8);
            byte[] offsetByte = Arrays.copyOfRange(decryptedData, idx, idx + 4);
            idx += 4;
            byte[] sizeByte = Arrays.copyOfRange(decryptedData, idx, idx + 4);
            idx += 4;
            fileList.add(new FileMeta(name, readUnit(offsetByte), readUnit(sizeByte)));
        }
        ExecutorService executor = Executors.newFixedThreadPool(threadNum);
        CountDownLatch producerLatch = new CountDownLatch(1);
        CountDownLatch consumerLatch = new CountDownLatch(fileList.size());
        BlockingQueue<FileMeta> fileQueue = new ArrayBlockingQueue<>(100);
        executor.submit(() -> {
            try {
                for (FileMeta meta : fileList) {
                    fileQueue.put(meta);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } finally {
                producerLatch.countDown();
            }
        });
        for (int i = 0; i < threadNum; i++) {
            executor.submit(() -> {
                while (true) {
                    FileMeta meta;
                    try {
                        if (producerLatch.getCount() == 0 && fileQueue.isEmpty()) {
                            break;
                        }
                        meta = fileQueue.poll(1, TimeUnit.SECONDS);
                        if (meta == null) {
                            continue;
                        }
                        String outputFilePath = outputPath + File.separator + meta.getName();
                        Path outputFile = Paths.get(outputFilePath);
                        Files.createDirectories(outputFile.getParent());
                        long offset = meta.getOffset();
                        long size = meta.getSize();
                        if (offset + size > decryptedData.length) {
                            addAppInfo("警告", "文件数据越界：" + meta.getName());
                            consumerLatch.countDown();
                            continue;
                        }
                        byte[] fileData = Arrays.copyOfRange(decryptedData, (int) offset, (int) (offset + size));
                        Files.write(outputFile, fileData);
                    } catch (IOException | InterruptedException e) {
                        addAppInfo("警告", "解包错误：" + e.getMessage());
                    } finally {
                        consumerLatch.countDown();
                    }
                }
            });
        }
        try {
            consumerLatch.await();
            executor.shutdown();
            executor.awaitTermination(5, TimeUnit.MINUTES);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            executor.shutdownNow();
        }
        return fileList.size();
    }

    /**
     * 查询小程序信息
     */
    public Map<String, String> queryAppInfo(String appid) {
        Map<String, String> result = new HashMap<>();
        result.put("appid", appid);
        result.put("nickName", "未知小程序");
        result.put("userName", "");
        result.put("description", "");
        result.put("principalName", "");
        String url = "https://kainy.cn/api/weapp/info/";
        RequestBody body = RequestBody.create(
                "{\"appid\":\"" + appid + "\"}",
                MediaType.parse("application/json;charset=utf-8")
        );
        Request request = new Request.Builder()
                .url(url)
                .post(body)
                .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36")
                .build();
        try (Response response = okHttpClient.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                addAppInfo("警告", "查询小程序信息失败：HTTP " + response.code());
                return result;
            }
            String responseBody = response.body().string();
            JsonNode jsonNode = objectMapper.readTree(responseBody);
            if (jsonNode == null) {
                addAppInfo("警告", "查询小程序信息失败：接口返回空JSON");
                return result;
            }
            JsonNode codeNode = jsonNode.get("code");
            int code = codeNode != null ? codeNode.asInt(-1) : -1;
            JsonNode dataNode = jsonNode.get("data");
            if (dataNode == null || dataNode.isNull()) {
                addAppInfo("警告", "小程序 " + appid + " 未收录：接口返回无数据");
                return result;
            }
            if (code != 0) {
                JsonNode msgNode = jsonNode.get("message");
                String msg = msgNode != null ? msgNode.asText("未知错误") : "未知错误";
                addAppInfo("警告", "小程序 " + appid + " 未收录：" + msg);
                return result;
            }
            result.put("nickName", getJsonNodeValue(dataNode, "nickname", "未知小程序"));
            result.put("userName", getJsonNodeValue(dataNode, "username", ""));
            result.put("description", getJsonNodeValue(dataNode, "description", ""));
            result.put("principalName", getJsonNodeValue(dataNode, "principal_name", ""));
        } catch (IOException e) {
            addAppInfo("警告", "查询小程序信息失败：" + e.getMessage());
        }
        return result;
    }

    /**
     * 信息泄露检测
     */
    private void infoLeakDetect(String outputPath) {
        try {
            Files.walkFileTree(Paths.get(outputPath), new SimpleFileVisitor<Path>() {
                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                    // 读取文件内容（编码容错）
                    String content;
                    try {
                        content = new String(Files.readAllBytes(file), StandardCharsets.UTF_8);
                    } catch (Exception e) {
                        content = new String(Files.readAllBytes(file), Charset.defaultCharset());
                    }

                    // 提取API接口
                    String[] fileLines = content.split("\r?\n", -1);
                    java.util.regex.Matcher urlMatcher = customApiPattern.matcher(content);
                    while (urlMatcher.find()) {
                        String url = null;
                        for (int i = 1; i <= 5; i++) {
                            String group = urlMatcher.group(i);
                            if (group != null && !group.trim().isEmpty()) {
                                url = group.trim();
                                break;
                            }
                        }
                        if (url == null || url.isEmpty()) continue;

                        // 提取匹配位置周围的源码上下文（前后各5行）
                        String apiContext = "";
                        try {
                            int matchPos = urlMatcher.start();
                            int lineNum = 0, charCount = 0;
                            for (int li = 0; li < fileLines.length; li++) {
                                charCount += fileLines[li].length() + 1;
                                if (charCount > matchPos) { lineNum = li; break; }
                            }
                            StringBuilder ctx = new StringBuilder();
                            int ctxStart = Math.max(0, lineNum - 5);
                            int ctxEnd = Math.min(fileLines.length - 1, lineNum + 5);
                            for (int li = ctxStart; li <= ctxEnd; li++) {
                                String l = fileLines[li].replace('\t', ' ');
                                ctx.append("    ").append(li + 1).append("| ").append(l);
                                if (l.length() > 120) ctx.append("...");
                                ctx.append("\n");
                            }
                            if (ctx.length() > 800) ctx = new StringBuilder(ctx.substring(0, 800) + "...");
                            apiContext = ctx.toString();
                        } catch (Exception ignored) {}

                        boolean needFilter = false;
                        //过滤api前端路径
                        for (String prefix : prefixBlacklist) {
                            if (url.contains(prefix)) {
                                needFilter = true;
                                break;
                            }
                        }
                        // 无参数URL：过滤黑名单后缀
                        if (!needFilter && !url.contains("?")) {
                            String urlSuffix = getUrlSuffix(url);
                            if (!urlSuffix.isEmpty() && suffixBlacklist.contains(urlSuffix)) {
                                needFilter = true;
                            }
                        }

                        // 非过滤项添加到API列表
                        if (!needFilter) {
                            apiInfoList.add(new ApiInfo(apiIndex++, file.toString().replace(outputPath,""), url, apiContext));
                        }
                    }

                    // 检测敏感信息（所有文件都扫描）
                    for (Map.Entry<String, Pattern> entry : customSensitivePatterns.entrySet()) {
                        String type = entry.getKey();
                        Pattern pattern = entry.getValue();
                        java.util.regex.Matcher matcher = pattern.matcher(content);
                        while (matcher.find()) {
                            String sensitiveContent = matcher.group();
                            sensitiveInfoList.add(new SensitiveInfo(file.toString().replace(outputPath,""), type, sensitiveContent));
                        }
                    }
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult visitFileFailed(Path file, IOException exc) throws IOException {
                    return FileVisitResult.CONTINUE;
                }
            });
        } catch (IOException e) {
            addAppInfo("错误信息", "❌ 信息泄露检测失败：" + e.getMessage());
        }
    }

    // 获取url后缀名
    private String getUrlSuffix(String url) {
        String cleanUrl = url.split("\\?")[0].split("#")[0];
        int lastDotIndex = cleanUrl.lastIndexOf(".");
        if (lastDotIndex == -1 || lastDotIndex == cleanUrl.length() - 1) {
            return "";
        }
        return cleanUrl.substring(lastDotIndex + 1).toLowerCase().replace(".", "");
    }
    // 小程序信息添加UI
    public void addAppInfo(String key, String value) {
        appInfoList.add(new AppInfo(key, value));
    }
    // 清除文件
    private void removeWxFile(Path path, String message) {
        try {
            Files.walkFileTree(path, new SimpleFileVisitor<Path>() {
                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                    Files.delete(file);
                    return FileVisitResult.CONTINUE;
                }
                @Override
                public FileVisitResult postVisitDirectory(Path dir, IOException exc) throws IOException {
                    Files.delete(dir);
                    return FileVisitResult.CONTINUE;
                }
            });
            addAppInfo("清理状态", "✅ 清除" + message + "成功！");
        } catch (IOException e) {
            addAppInfo("警告", "⚠️ 清除" + message + "失败：" + e.getMessage());
        }
    }

    public String extractWxId() {
        Pattern pattern = Pattern.compile("\\bwx[a-f0-9]{16}\\b");
        java.util.regex.Matcher matcher = pattern.matcher(this.wxapkgFilePath);
        return matcher.find() ? matcher.group() : "unknown";
    }

    private long readUnit(byte[] b) {
        int len = b.length;
        switch (len) {
            case 1:
                return b[0] & 0xFF;
            case 2:
                return ((b[0] & 0xFF) << 8) | (b[1] & 0xFF);
            case 4:
                return ((long) (b[0] & 0xFF) << 24) | ((long) (b[1] & 0xFF) << 16) | ((long) (b[2] & 0xFF) << 8) | (b[3] & 0xFF);
            default:
                return 0;
        }
    }

    private String getJsonNodeValue(JsonNode parentNode, String fieldName, String defaultValue) {
        JsonNode node = parentNode.get(fieldName);
        if (node == null || node.isNull() || node.asText().isEmpty()) {
            return defaultValue;
        }
        return node.asText();
    }

    // ========== 结构化结果内部类 ==========
    public static class AppInfo {
        private final String key;
        private final String value;
        public AppInfo(String key, String value) {
            this.key = key;
            this.value = value;
        }
        public String getKey() { return key; }
        public String getValue() { return value; }
    }

    public static class ApiInfo {
        private final int index;
        private final String file;
        private final String api;
        private final String context;
        public ApiInfo(int index, String file, String api, String context) {
            this.index = index;
            this.file = file;
            this.api = api;
            this.context = context;
        }
        public int getIndex() { return index; }
        public String getFile() { return file; }
        public String getApi() { return api; }
        public String getContext() { return context; }
    }

    public static class SensitiveInfo {
        private final String file;
        private final String type;
        private final String content;
        public SensitiveInfo(String file, String type, String content) {
            this.file = file;
            this.type = type;
            this.content = content;
        }
        public String getFile() { return file; }
        public String getType() { return type; }
        public String getContent() { return content; }
    }

    // ========== 获取结果的方法 ==========
    public List<AppInfo> getAppInfoList() { return appInfoList; }
    public List<ApiInfo> getApiInfoList() { return apiInfoList; }
    public List<SensitiveInfo> getSensitiveInfoList() { return sensitiveInfoList; }

    public String getPackageType() {
        File wxapkgFile = new File(this.wxapkgFilePath);
        return wxapkgFile.getName().equals("__APP__.wxapkg") ? "主包" : "分包";
    }

    /**
     * wxapkg文件元信息
     */
    static class FileMeta {
        private final String name;
        private final long offset;
        private final long size;
        public FileMeta(String name, long offset, long size) {
            this.name = name;
            this.offset = offset;
            this.size = size;
        }
        public String getName() { return name; }
        public long getOffset() { return offset; }
        public long getSize() { return size; }
    }
}