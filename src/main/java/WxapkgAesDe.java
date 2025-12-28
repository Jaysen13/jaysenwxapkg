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
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.spec.KeySpec;
import java.util.Arrays;

/**
 * 微信小程序wxapkg AES解密工具
 */
public class WxapkgAesDe {
    // 微信小程序包自定义标识
    private static final String WXAPKG_FLAG = "V1MMWX";
    private static final int WXAPKG_FLAG_LEN = WXAPKG_FLAG.length();
    // 默认参数
    private static final String DEFAULT_IV = "the iv: 16 bytes";
    private static final String DEFAULT_SALT = "saltiest";
    private static final int AES_KEY_SIZE = 32; // 256位密钥
    private static final int PBKDF2_ITERATIONS = 1000;

    /**
     * 解密wxapkg文件
     * @param wxid 微信小程序ID（必填）
     * @param encryptedFile 加密的wxapkg文件路径
     * @param decryptedFile 解密后的输出文件路径
     * @throws Exception 解密失败抛出异常
     */
    public void decrypt(String wxid, String encryptedFile, String decryptedFile) throws Exception {
        decrypt(wxid, DEFAULT_IV, DEFAULT_SALT, encryptedFile, decryptedFile);
    }

    /**
     * 自定义IV/Salt的解密方法
     * @param wxid 微信小程序ID
     * @param iv 初始向量（默认：the iv: 16 bytes）
     * @param salt 盐值（默认：saltiest）
     * @param encryptedFile 加密文件路径
     * @param decryptedFile 解密输出路径
     * @throws Exception 解密异常
     */
    public void decrypt(String wxid, String iv, String salt, String encryptedFile, String decryptedFile) throws Exception {
        // 1. 校验文件是否存在
        File srcFile = new File(encryptedFile);
        if (!srcFile.exists() || !srcFile.isFile()) {
            throw new Exception("加密文件不存在：" + encryptedFile);
        }

        // 2. 读取文件字节
        byte[] dataByte = readFileToBytes(srcFile);

        // 3. 校验文件头标识
        String flag = new String(Arrays.copyOfRange(dataByte, 0, WXAPKG_FLAG_LEN), StandardCharsets.UTF_8);
        if (!WXAPKG_FLAG.equals(flag)) {
            throw new Exception("文件无需解密，或不是加密的wxapkg包（标识不匹配：" + flag + "）");
        }

        // 4. PBKDF2生成AES密钥（兼容Python的PBKDF2逻辑）
        SecretKey secretKey = generatePBKDF2Key(wxid, salt);
        SecretKeySpec aesKey = new SecretKeySpec(secretKey.getEncoded(), "AES");

        // 5. AES-CBC解密前1024字节（跳过FLAG）
        byte[] encryptedHead = Arrays.copyOfRange(dataByte, WXAPKG_FLAG_LEN, WXAPKG_FLAG_LEN + 1024);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding"); // Python的PKCS7Padding兼容PKCS5Padding
        cipher.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(iv.getBytes(StandardCharsets.UTF_8)));
        byte[] originHead = cipher.doFinal(encryptedHead);

        // 6. 计算XOR密钥（默认0x66，wxid长度>=2则取倒数第二个字符的ASCII）
        int xorKey = 0x66;
        if (wxid != null && wxid.length() >= 2) {
            xorKey = (int) wxid.charAt(wxid.length() - 2);
        }

        // 7. 剩余字节进行XOR解密
        byte[] afData = Arrays.copyOfRange(dataByte, WXAPKG_FLAG_LEN + 1024, dataByte.length);
        byte[] xorData = xorDecrypt(afData, xorKey);

        // 8. 拼接解密后的数据（截断前1023字节 + XOR数据）
        byte[] originData = new byte[1023 + xorData.length];
        System.arraycopy(originHead, 0, originData, 0, 1023);
        System.arraycopy(xorData, 0, originData, 1023, xorData.length);

        // 9. 保存解密后的文件
        writeBytesToFile(originData, new File(decryptedFile));
    }

    /**
     * PBKDF2生成AES密钥（复刻Python的PBKDF2逻辑）
     */
    private SecretKey generatePBKDF2Key(String password, String salt) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        KeySpec spec = new PBEKeySpec(
                password.toCharArray(),
                salt.getBytes(StandardCharsets.UTF_8),
                PBKDF2_ITERATIONS,
                AES_KEY_SIZE * 8 // 位数（32字节=256位）
        );
        return factory.generateSecret(spec);
    }

    /**
     * XOR异或解密
     */
    private byte[] xorDecrypt(byte[] data, int xorKey) {
        byte[] result = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            result[i] = (byte) (data[i] ^ xorKey);
        }
        return result;
    }

    /**
     * 文件读取为字节数组
     */
    private byte[] readFileToBytes(File file) throws Exception {
        try (FileInputStream fis = new FileInputStream(file)) {
            byte[] buffer = new byte[(int) file.length()];
            fis.read(buffer);
            return buffer;
        }
    }

    /**
     * 字节数组写入文件
     */
    private void writeBytesToFile(byte[] data, File file) throws Exception {
        File parentDir = file.getParentFile();
        if (!parentDir.exists()) {
            parentDir.mkdirs();
        }
        try (FileOutputStream fos = new FileOutputStream(file)) {
            fos.write(data);
        }
    }

    /**
     * 快速校验文件是否为加密的wxapkg
     */
    public boolean isEncryptedWxapkg(String filePath) throws Exception {
        File file = new File(filePath);
        if (!file.exists()) return false;
        byte[] header = Arrays.copyOfRange(readFileToBytes(file), 0, WXAPKG_FLAG_LEN);
        return WXAPKG_FLAG.equals(new String(header, StandardCharsets.UTF_8));
    }
}