import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * 独立测试类：扫描反编译后的文件夹，用指定正则匹配API并统计数量
 */
public class WxapkgApiTestMain {
    private static String getUrlSuffix(String url) {
        // 去掉URL中的路径参数/锚点（比如 ?a=1 或 #hash）
        String cleanUrl = url.split("\\?")[0].split("#")[0];
        // 找到最后一个"."的位置
        int lastDotIndex = cleanUrl.lastIndexOf(".");
        if (lastDotIndex == -1 || lastDotIndex == cleanUrl.length() - 1) {
            return ""; // 无后缀/后缀为空
        }
        // 提取后缀并转小写
        return cleanUrl.substring(lastDotIndex + 1).toLowerCase().replace(".", "");
    }
    public static void main(String[] args) {
        System.out.println(System.getProperty("user.home"));
    }
}