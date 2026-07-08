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
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public class Config {
    // 默认API提取正则（支持URL、绝对路径、相对路径、带扩展名等多种格式）
    static Pattern DEFAULT_API_PATTERN = Pattern.compile(
        "(?:\"|')" +
        "(" +
            // 1. 完整URL: https://domain.com/path, //domain.com/path
            "((?:[a-zA-Z]{1,10}://|//)[^\"'/]{1,}\\.[a-zA-Z]{2,}[^\"']{0,})" +
            "|" +
            // 2. 绝对/相对路径: /order/list, ./api, ../user/info (支持多级路径)
            "((?:/|\\.\\./|\\./)[a-zA-Z0-9_\\-.][^\"'><,;| *()(%%$^\\\\\\[\\]]{0,}(?:/[^\"'><,;|()*]{1,})*)" +
            "|" +
            // 3. 无前导/的相对API路径: order/list, api/v1/users, user/info
            "([a-zA-Z][a-zA-Z0-9_\\-]*/[a-zA-Z0-9_\\-./]{1,})" +
            "|" +
            // 4. 带扩展名的路径（必须有至少一个/）: api/user.php, data/list.json?action=get
            "([a-zA-Z0-9_\\-/]{1,}/[a-zA-Z0-9_\\-./]{0,}\\.[a-zA-Z]{1,6}(?:\\?[^\"']{0,}|))" +
        ")" +
        "(?:\"|')"
    );

    // 默认敏感信息正则
    static Map<String, Pattern> DEFAULT_SENSITIVE_PATTERNS;
    static {
        DEFAULT_SENSITIVE_PATTERNS = new HashMap<>();
        DEFAULT_SENSITIVE_PATTERNS.put("微信小程序 session_key 泄露", Pattern.compile("(?i)\\bsession_key\\b"));
        DEFAULT_SENSITIVE_PATTERNS.put("AppSecret 泄露", Pattern.compile("(?i)\\b\\w*secret\\b"));
        DEFAULT_SENSITIVE_PATTERNS.put("手机号", Pattern.compile("1[3-9]\\d{9}"));
        DEFAULT_SENSITIVE_PATTERNS.put("身份证号", Pattern.compile("\\b\\d{17}([0-9]|X|x)\\b"));
        DEFAULT_SENSITIVE_PATTERNS.put("邮箱地址", Pattern.compile("[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,4}"));
        DEFAULT_SENSITIVE_PATTERNS.put("IP地址", Pattern.compile("^(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\\.(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\\.(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\\.(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"));
        DEFAULT_SENSITIVE_PATTERNS.put("车牌", Pattern.compile("^[京津沪渝冀豫云辽黑湘皖鲁新苏浙赣鄂桂甘晋蒙陕吉闽贵粤青藏川宁琼使领A-Z]{1}[A-Z]{1}[A-Z0-9]{4}[A-Z0-9挂学警港澳]{1}$"));
    }
    // 默认API黑名单
    public static final Set<String> DEFAULT_PREFIX_BLACKLIST = new HashSet<>(Arrays.asList(
            "pages/", "components/", "static/", "uni_modules/","uview-ui/","uview-plus/","package/"
    ));

    // 默认API后缀黑名单
    static Set<String> DEFAULT_SUFFIX_BLACKLIST = new HashSet<>(Arrays.asList(
            "js", "jpg", "png", "jpeg", "gif", "svg", "wxml", "wxss"
    ));

    // 默认打开的路径（动态计算users下最新32位文件夹）
    static String DEFAULT_WXAPKGPATH = findLatestWxapkgPath();

    /**
     * 动态查找微信小程序包路径：
     * C:\\Users\\{用户名}\\AppData\\Roaming\\Tencent\\xwechat\\radium\\users\\{最近修改的32位文件夹}\\applet\\packages\\
     */
    private static String findLatestWxapkgPath() {
        String userHome = System.getProperty("user.home");
        String usersDir = userHome + "\\AppData\\Roaming\\Tencent\\xwechat\\radium\\users\\";
        File usersFolder = new File(usersDir);

        if (!usersFolder.exists() || !usersFolder.isDirectory()) {
            // 回退到旧版默认路径
            return userHome + "\\AppData\\Roaming\\Tencent\\xwechat\\radium\\Applet\\packages\\";
        }

        File[] subDirs = usersFolder.listFiles(File::isDirectory);
        if (subDirs == null || subDirs.length == 0) {
            return userHome + "\\AppData\\Roaming\\Tencent\\xwechat\\radium\\Applet\\packages\\";
        }

        // 筛选32位长度命名的文件夹，取修改日期最近的
        File latestDir = null;
        long latestTime = 0;
        for (File dir : subDirs) {
            if (dir.getName().length() == 32) {
                long modified = dir.lastModified();
                if (modified > latestTime) {
                    latestTime = modified;
                    latestDir = dir;
                }
            }
        }

        if (latestDir != null) {
            return latestDir.getAbsolutePath() + "\\applet\\packages\\";
        }

        // 无32位文件夹时回退
        return userHome + "\\AppData\\Roaming\\Tencent\\xwechat\\radium\\Applet\\packages\\";
    }

    // ========== 配置实体类（封装UI传入的参数） ==========
    public static class SavedConfig {
        private String apiRegex; // API提取正则字符串
        private Map<String, String> sensitiveRegexMap; // 敏感信息正则（类型:正则）
        private Set<String> suffixBlacklist; // 后缀黑名单
        private Set<String> prefixBlacklist; // 前缀黑名单
        private String wxapkgPath;
        // AI配置字段（可为null，兼容旧配置文件）
        private String aiApiKey;
        private String aiModelUrl;
        private String aiModelName;
        private String aiTimeout;
        private String aiContextLength;
        private String aiExtraHeaders;
        private String aiPromptTemplate;
        private String aiDomain;
        // 空构造（Jackson反序列化需要）
        public SavedConfig() {}

        // 带参构造（UI传入）
        public SavedConfig(String apiRegex, Map<String, String> sensitiveRegexMap, Set<String> suffixBlacklist,Set<String> prefixBlacklist,String wxapkgPath) {
            this.apiRegex = apiRegex;
            this.sensitiveRegexMap = sensitiveRegexMap;
            this.suffixBlacklist = suffixBlacklist;
            this.prefixBlacklist = prefixBlacklist;
            this.wxapkgPath = wxapkgPath;
        }

        // Getter & Setter
        public String getApiRegex() { return apiRegex; }
        public void setApiRegex(String apiRegex) { this.apiRegex = apiRegex; }
        public Map<String, String> getSensitiveRegexMap() { return sensitiveRegexMap; }
        public void setSensitiveRegexMap(Map<String, String> sensitiveRegexMap) { this.sensitiveRegexMap = sensitiveRegexMap; }
        public Set<String> getSuffixBlacklist() { return suffixBlacklist; }
        public void setSuffixBlacklist(Set<String> suffixBlacklist) { this.suffixBlacklist = suffixBlacklist; }
        public Set<String> getPrefixBlacklist() { return prefixBlacklist; }
        public void setPrefixBlacklist(Set<String> prefixBlacklist) { this.prefixBlacklist = prefixBlacklist; }
        public String getwxapkgPath() { return wxapkgPath;}
        public void setWxapkgPath(String wxapkgPath) {this.wxapkgPath = wxapkgPath;}
        // AI配置 Getter/Setter
        public String getAiApiKey() { return aiApiKey; }
        public void setAiApiKey(String aiApiKey) { this.aiApiKey = aiApiKey; }
        public String getAiModelUrl() { return aiModelUrl; }
        public void setAiModelUrl(String aiModelUrl) { this.aiModelUrl = aiModelUrl; }
        public String getAiModelName() { return aiModelName; }
        public void setAiModelName(String aiModelName) { this.aiModelName = aiModelName; }
        public String getAiTimeout() { return aiTimeout; }
        public void setAiTimeout(String aiTimeout) { this.aiTimeout = aiTimeout; }
        public String getAiContextLength() { return aiContextLength; }
        public void setAiContextLength(String aiContextLength) { this.aiContextLength = aiContextLength; }
        public String getAiExtraHeaders() { return aiExtraHeaders; }
        public void setAiExtraHeaders(String aiExtraHeaders) { this.aiExtraHeaders = aiExtraHeaders; }
        public String getAiPromptTemplate() { return aiPromptTemplate; }
        public void setAiPromptTemplate(String aiPromptTemplate) { this.aiPromptTemplate = aiPromptTemplate; }
        public String getAiDomain() { return aiDomain; }
        public void setAiDomain(String aiDomain) { this.aiDomain = aiDomain; }
    }

    // 将用户输入的逗号分隔字符串转为前缀黑名单Set
    public static Set<String> parsePrefixTextToSet(String text) {
        Set<String> set = new HashSet<>();
        if (text == null || text.trim().isEmpty()) {
            return set;
        }
        String[] items = text.trim().split(",");
        for (String item : items) {
            String trimItem = item.trim();
            if (!trimItem.isEmpty()) {
                set.add(trimItem);
            }
        }
        return set;
    }
    public static String convertPrefixSetToText(Set<String> set) {
        if (set == null || set.isEmpty()) {
            return "";
        }
        return String.join(",", set);
    }

    /**
     * 保存配置到JSON文件（联动UI，接收自定义参数）
     * @param customApiRegex UI输入的API正则（空则用默认）
     * @param customSensitiveRegexMap UI输入的敏感信息正则Map（空则用默认）
     * @param customSuffixBlacklist UI输入的后缀黑名单（空则用默认）
     * @throws IOException 保存异常
     */
    public static void saveConfigFile(String customApiRegex, Map<String, String> customSensitiveRegexMap, Set<String> customSuffixBlacklist,Set<String> customprefixBlacklist,String wxapkgPath) throws IOException {
        // 1. 动态拼接路径：C:/Users/{USER}/.burp/jaysenwxapkg.json
        String userName = System.getProperty("user.name");
        String configPath = String.format("C:/Users/%s/.burp/jaysenwxapkg/jaysenwxapkg.json", userName);
        File configFile = new File(configPath);

        // 2. 自动创建jaysenwxapkg目录
        if (!configFile.getParentFile().exists()) {
            configFile.getParentFile().mkdirs();
        }

        // 3. 处理空值（兜底用默认配置）
        String finalApiRegex = (customApiRegex == null || customApiRegex.trim().isEmpty())
                ? DEFAULT_API_PATTERN.pattern() : customApiRegex.trim();

        Map<String, String> finalSensitiveMap = (customSensitiveRegexMap == null || customSensitiveRegexMap.isEmpty())
                ? DEFAULT_SENSITIVE_PATTERNS.entrySet().stream()
                .collect(HashMap::new, (m, e) -> m.put(e.getKey(), e.getValue().pattern()), HashMap::putAll)
                : customSensitiveRegexMap;
        Set<String> finalSuffixBlacklist = (customSuffixBlacklist == null || customSuffixBlacklist.isEmpty()) ? DEFAULT_SUFFIX_BLACKLIST : customSuffixBlacklist;
        String finalwxapkgPath = (wxapkgPath == null || wxapkgPath.isEmpty()) ? DEFAULT_WXAPKGPATH : wxapkgPath;

        // 4. 封装为配置实体
        SavedConfig savedConfig = new SavedConfig(finalApiRegex, finalSensitiveMap, finalSuffixBlacklist,customprefixBlacklist,finalwxapkgPath);

        // 5. Jackson序列化为格式化JSON
        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.enable(SerializationFeature.INDENT_OUTPUT); // 格式化换行
        String jsonContent = objectMapper.writeValueAsString(savedConfig);

        // 6. 写入文件（UTF-8避免中文乱码）
        Files.write(Paths.get(configPath), jsonContent.getBytes(StandardCharsets.UTF_8));
    }

    // ========== 核心：加载配置（初始化UI时读取） ==========
    /**
     * 从JSON文件加载配置（无配置则返回默认）
     * @return 保存的配置（兜底默认值）
     */
    public static SavedConfig loadConfigFile() {
        try {
            // 1. 获取配置文件路径
            String userName = System.getProperty("user.name");
            String configPath = String.format("C:/Users/%s/.burp/jaysenwxapkg/jaysenwxapkg.json", userName);
            File configFile = new File(configPath);

            // 2. 文件不存在 → 返回默认配置
            if (!configFile.exists()) {
                Map<String, String> defaultSensitiveMap = DEFAULT_SENSITIVE_PATTERNS.entrySet().stream()
                        .collect(HashMap::new, (m, e) -> m.put(e.getKey(), e.getValue().pattern()), HashMap::putAll);
                return new SavedConfig(DEFAULT_API_PATTERN.pattern(), defaultSensitiveMap, DEFAULT_SUFFIX_BLACKLIST,DEFAULT_PREFIX_BLACKLIST,DEFAULT_WXAPKGPATH);
            }

            // 3. 读取并反序列化JSON
            ObjectMapper objectMapper = new ObjectMapper();
            return objectMapper.readValue(configFile, SavedConfig.class);

        } catch (Exception e) {
            // 解析失败 → 返回默认配置
            Map<String, String> defaultSensitiveMap = DEFAULT_SENSITIVE_PATTERNS.entrySet().stream()
                    .collect(HashMap::new, (m, e2) -> m.put(e2.getKey(), e2.getValue().pattern()), HashMap::putAll);
            return new SavedConfig(DEFAULT_API_PATTERN.pattern(), defaultSensitiveMap, DEFAULT_SUFFIX_BLACKLIST,DEFAULT_PREFIX_BLACKLIST,DEFAULT_WXAPKGPATH);
        }
    }

    // ========== 工具方法：敏感信息正则字符串（UI多行）→ Map ==========
    /**
     * 把UI中"类型:正则"的多行字符串转换为Map
     * @param sensitiveText UI文本域内容（如：手机号:1[3-9]\\d{9}\\n身份证号:...）
     * @return 类型→正则的Map（解析失败返回默认）
     */
    public static Map<String, String> parseSensitiveTextToMap(String sensitiveText) {
        Map<String, String> result = new HashMap<>();
        if (sensitiveText == null || sensitiveText.trim().isEmpty()) {
            // 空值返回默认
            return DEFAULT_SENSITIVE_PATTERNS.entrySet().stream()
                    .collect(HashMap::new, (m, e) -> m.put(e.getKey(), e.getValue().pattern()), HashMap::putAll);
        }

        try {
            String[] lines = sensitiveText.split("\\n");
            for (String line : lines) {
                line = line.trim();
                if (line.isEmpty() || !line.contains(":")) continue;
                // 分割为类型和正则（只分割第一个冒号，避免正则含冒号）
                String[] parts = line.split(":", 2);
                String type = parts[0].trim();
                String regex = parts[1].trim();
                if (!type.isEmpty() && !regex.isEmpty()) {
                    result.put(type, regex);
                }
            }
            return result.isEmpty() ? DEFAULT_SENSITIVE_PATTERNS.entrySet().stream()
                    .collect(HashMap::new, (m, e) -> m.put(e.getKey(), e.getValue().pattern()), HashMap::putAll) : result;
        } catch (Exception e) {
            return DEFAULT_SENSITIVE_PATTERNS.entrySet().stream()
                    .collect(HashMap::new, (m, e1) -> m.put(e1.getKey(), e1.getValue().pattern()), HashMap::putAll);
        }
    }

    // ========== 工具方法：后缀黑名单字符串（UI逗号分隔）→ Set ==========
    /**
     * 把UI中逗号分隔的后缀字符串转换为Set
     * @param suffixText UI输入框内容（如：js,wxml,wxss）
     * @return 后缀Set（解析失败返回默认）
     */
    public static Set<String> parseSuffixTextToSet(String suffixText) {
        Set<String> result = new HashSet<>();
        if (suffixText == null || suffixText.trim().isEmpty()) {
            return DEFAULT_SUFFIX_BLACKLIST;
        }

        try {
            String[] suffixes = suffixText.split(",");
            for (String suffix : suffixes) {
                suffix = suffix.trim().toLowerCase();
                if (!suffix.isEmpty()) {
                    result.add(suffix);
                }
            }
            return result.isEmpty() ? DEFAULT_SUFFIX_BLACKLIST : result;
        } catch (Exception e) {
            return DEFAULT_SUFFIX_BLACKLIST;
        }
    }

    // ========== 工具方法：敏感信息Map → UI多行字符串 ==========
    /**
     * 把敏感信息Map转换为UI文本域的多行字符串（类型:正则）
     * @param sensitiveMap 敏感信息Map
     * @return 多行字符串
     */
    public static String convertSensitiveMapToText(Map<String, String> sensitiveMap) {
        if (sensitiveMap == null || sensitiveMap.isEmpty()) {
            return DEFAULT_SENSITIVE_PATTERNS.entrySet().stream()
                    .map(entry -> entry.getKey() + ":" + entry.getValue().pattern())
                    .collect(Collectors.joining("\n"));
        }
        return sensitiveMap.entrySet().stream()
                .map(entry -> entry.getKey() + ":" + entry.getValue())
                .collect(Collectors.joining("\n"));
    }

    // ========== 工具方法：后缀Set → UI逗号分隔字符串 ==========
    /**
     * 把后缀Set转换为UI输入框的逗号分隔字符串
     * @param suffixSet 后缀Set
     * @return 逗号分隔字符串
     */
    public static String convertSuffixSetToText(Set<String> suffixSet) {
        if (suffixSet == null || suffixSet.isEmpty()) {
            return String.join(",", DEFAULT_SUFFIX_BLACKLIST);
        }
        return String.join(",", suffixSet);
    }

    // ========== AI配置：保存 ==========
    /**
     * 保存AI配置到已有配置文件（合并更新，不影响其他字段）
     */
    public static void saveAiConfig(String apiKey, String modelUrl, String modelName,
                                     String timeout, String contextLength, String extraHeaders,
                                     String promptTemplate, String domain) {
        try {
            String userName = System.getProperty("user.name");
            String configPath = String.format("C:/Users/%s/.burp/jaysenwxapkg/jaysenwxapkg.json", userName);
            File configFile = new File(configPath);

            // 读取已有配置（不存在则创建默认）
            SavedConfig config;
            if (configFile.exists()) {
                ObjectMapper om = new ObjectMapper();
                config = om.readValue(configFile, SavedConfig.class);
            } else {
                config = loadConfigFile(); // 默认配置
            }

            // 更新AI字段
            config.setAiApiKey(apiKey);
            config.setAiModelUrl(modelUrl);
            config.setAiModelName(modelName);
            config.setAiTimeout(timeout);
            config.setAiContextLength(contextLength);
            config.setAiExtraHeaders(extraHeaders);
            config.setAiPromptTemplate(promptTemplate);
            config.setAiDomain(domain);

            // 写回文件（确保目录存在）
            if (!configFile.getParentFile().exists()) {
                configFile.getParentFile().mkdirs();
            }
            ObjectMapper om = new ObjectMapper();
            om.enable(SerializationFeature.INDENT_OUTPUT);
            String json = om.writeValueAsString(config);
            Files.write(Paths.get(configPath), json.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            // 静默失败，不影响主流程
        }
    }

    // ========== AI配置：加载 ==========
    /**
     * 从配置文件加载AI配置字段
     * @return SavedConfig（AI字段可能为null，调用方需用默认值兜底）
     */
    public static SavedConfig loadAiConfig() {
        return loadConfigFile(); // SavedConfig已包含所有字段，直接复用
    }
}


