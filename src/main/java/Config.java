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
    // 默认API提取正则
    static Pattern DEFAULT_API_PATTERN = Pattern.compile("(?:\"|')(((?:[a-zA-Z]{1,10}://|//)[^\"'/]{1,}\\.([a-zA-Z]{2,})[^\"']{0,})|((?:/|\\.\\./|\\./)[^\"'><,;| *()(%%$^/\\\\\\[\\]][^\"'><,;|()]{1,})|([a-zA-Z0-9_\\-/]{1,}/[a-zA-Z0-9_\\-/]{1,}\\.(?:[a-zA-Z]{1,4}|action)(?:[\\?|/][^\"|']{0,}|))|([a-zA-Z0-9_\\-]{1,}\\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)(?:\\?[^\"|']{0,}|)))(?:\"|')");

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

    // 默认URL后缀黑名单（仅用于过滤无参数的无用URL）
    static Set<String> DEFAULT_SUFFIX_BLACKLIST = new HashSet<>(Arrays.asList(
            "js", "jpg", "png", "jpeg", "gif", "svg", "wxml", "wxss", "json", "html"
    ));
    // ========== 配置实体类（封装UI传入的参数） ==========
    public static class SavedConfig {
        private String apiRegex; // API提取正则字符串
        private Map<String, String> sensitiveRegexMap; // 敏感信息正则（类型:正则）
        private Set<String> suffixBlacklist; // 后缀黑名单

        // 空构造（Jackson反序列化需要）
        public SavedConfig() {}

        // 带参构造（UI传入）
        public SavedConfig(String apiRegex, Map<String, String> sensitiveRegexMap, Set<String> suffixBlacklist) {
            this.apiRegex = apiRegex;
            this.sensitiveRegexMap = sensitiveRegexMap;
            this.suffixBlacklist = suffixBlacklist;
        }

        // Getter & Setter
        public String getApiRegex() { return apiRegex; }
        public void setApiRegex(String apiRegex) { this.apiRegex = apiRegex; }
        public Map<String, String> getSensitiveRegexMap() { return sensitiveRegexMap; }
        public void setSensitiveRegexMap(Map<String, String> sensitiveRegexMap) { this.sensitiveRegexMap = sensitiveRegexMap; }
        public Set<String> getSuffixBlacklist() { return suffixBlacklist; }
        public void setSuffixBlacklist(Set<String> suffixBlacklist) { this.suffixBlacklist = suffixBlacklist; }
    }


    /**
     * 保存配置到JSON文件（联动UI，接收自定义参数）
     * @param customApiRegex UI输入的API正则（空则用默认）
     * @param customSensitiveRegexMap UI输入的敏感信息正则Map（空则用默认）
     * @param customSuffixBlacklist UI输入的后缀黑名单（空则用默认）
     * @throws IOException 保存异常
     */
    public static void saveConfigFile(String customApiRegex, Map<String, String> customSensitiveRegexMap, Set<String> customSuffixBlacklist) throws IOException {
        // 1. 动态拼接路径：C:/Users/{USER}/.burp/jaysenwxapkg.json
        String userName = System.getProperty("user.name");
        String configPath = String.format("C:/Users/%s/.burp/jaysenwxapkg.json", userName);
        File configFile = new File(configPath);

        // 2. 自动创建.burp目录
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

        Set<String> finalSuffixBlacklist = (customSuffixBlacklist == null || customSuffixBlacklist.isEmpty())
                ? DEFAULT_SUFFIX_BLACKLIST : customSuffixBlacklist;

        // 4. 封装为配置实体
        SavedConfig savedConfig = new SavedConfig(finalApiRegex, finalSensitiveMap, finalSuffixBlacklist);

        // 5. Jackson序列化为格式化JSON
        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.enable(SerializationFeature.INDENT_OUTPUT); // 格式化换行
        String jsonContent = objectMapper.writeValueAsString(savedConfig);

        // 6. 写入文件（UTF-8避免中文乱码）
        Files.write(Paths.get(configPath), jsonContent.getBytes(StandardCharsets.UTF_8));
        System.out.println("✅ 配置已自动保存到：" + configPath);
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
            String configPath = String.format("C:/Users/%s/.burp/jaysenwxapkg.json", userName);
            File configFile = new File(configPath);

            // 2. 文件不存在 → 返回默认配置
            if (!configFile.exists()) {
                Map<String, String> defaultSensitiveMap = DEFAULT_SENSITIVE_PATTERNS.entrySet().stream()
                        .collect(HashMap::new, (m, e) -> m.put(e.getKey(), e.getValue().pattern()), HashMap::putAll);
                return new SavedConfig(DEFAULT_API_PATTERN.pattern(), defaultSensitiveMap, DEFAULT_SUFFIX_BLACKLIST);
            }

            // 3. 读取并反序列化JSON
            ObjectMapper objectMapper = new ObjectMapper();
            return objectMapper.readValue(configFile, SavedConfig.class);

        } catch (Exception e) {
            // 解析失败 → 返回默认配置
            System.err.println("⚠️ 加载配置失败，使用默认值：" + e.getMessage());
            Map<String, String> defaultSensitiveMap = DEFAULT_SENSITIVE_PATTERNS.entrySet().stream()
                    .collect(HashMap::new, (m, e2) -> m.put(e2.getKey(), e2.getValue().pattern()), HashMap::putAll);
            return new SavedConfig(DEFAULT_API_PATTERN.pattern(), defaultSensitiveMap, DEFAULT_SUFFIX_BLACKLIST);
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
}


