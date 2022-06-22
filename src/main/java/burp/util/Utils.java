package burp.util;

import burp.payload.IPoc;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

/**
 * @author : metaStor
 * @date : Created 2022/4/7
 * @description: 工具类
 * */
public class Utils {

    public static Random random = new Random();

    // 静态文件后缀
    public final static String[] STATIC_FILE_EXT = new String[]{
            "png",
            "jpg",
            "jpeg",
            "gif",
            "pdf",
            "bmp",
            "js",
            "css",
            "ico",
            "woff",
            "woff2",
            "ttf",
            "otf",
            "ttc",
            "svg",
            "psd",
            "exe",
            "zip",
            "rar",
            "7z",
            "msi",
            "tar",
            "gz",
            "mp3",
            "mp4",
            "mkv",
            "swf",
            "xls",
            "xlsx",
            "doc",
            "docx",
            "ppt",
            "pptx",
            "iso"
    };

    /**
     * MD5加密, 用于只扫描一次同类uri
     * @param src
     * @return hexadecimal string
     */
    public static String MD5(String src) {
        byte[] digest = null;
        try {
            MessageDigest md5 = MessageDigest.getInstance("MD5");
            digest = md5.digest(src.getBytes());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("MD5 Algorithm not found!");
        }
        return new BigInteger(1, digest).toString(16);
    }

    /**
     * 获取url的文件后缀
     * @param url
     * @return ext
     */
    public static String getUriExt(String url) {
        String pureUrl = url.substring(0, url.contains("?") ? url.indexOf("?") : url.length());
        return (pureUrl.lastIndexOf(".") > -1 ? pureUrl.substring(pureUrl.lastIndexOf(".") + 1) : "").toLowerCase();
    }

    /**
     * 取url的uri路径
     * @param url http://xxx:8080/api/auth-manager-microservice/v1/login/anon/apps?_t=1649647394555kna8
     * @return uri /api/auth-manager-microservice/v1/login/anon/
     */
    public static String getUri(String url) {
        url = url.replace("https://", "").replace("http://", "");  // 截去http://或https://
        String pureUrl = url.substring(0, url.contains("#") ? url.indexOf("#") : url.length());  // 排除锚点
        pureUrl = pureUrl.substring(0, pureUrl.contains("?") ? pureUrl.indexOf("?") : pureUrl.length());  // 排除参数
        pureUrl = pureUrl.substring(pureUrl.contains("/") ? pureUrl.indexOf("/") : pureUrl.length(), pureUrl.contains("/") ? pureUrl.lastIndexOf("/") : pureUrl.length());  // 取最后一个/之前的uri
        return pureUrl + "/";
    }

    /**
     * 判断状态码是否是异常
     * 异常响应码: 400, 500, 502, 503
     * @param status_code
     * @return
     */
    public static boolean isErrorStatusCode(int status_code) {
        return Arrays.stream(new Integer[]{ 400, 500, 502, 503 }).anyMatch(e -> e == status_code);
    }

    /**
     * 判断uri是否静态文件,
     * 使用传统的循环判断，时间复杂度为O(1)
     * @param url
     * @return true/false
     */
    public static boolean isStaticFile(String url) {
        for (String ext : STATIC_FILE_EXT) {
            if (ext.equalsIgnoreCase(Utils.getUriExt(url))) return true;
        }
        return false;
    }

    /**
     * 获取pocs包中的所有poc类
     * @param rangePocs
     * @return Map
     */
    public static IPoc[] getPocs(Integer[] rangePocs) {
        List<IPoc> pocs = new ArrayList<IPoc>();
        try {
            for (Integer no : rangePocs) {
                Class<?> poc = Class.forName("burp.payload.pocs.POC" + String.valueOf(no));
                pocs.add((IPoc) poc.newInstance());
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return pocs.toArray(new IPoc[0]);
    }

    /**
     * 随机取 n 个字符
     * @param n
     * @return String
     */
    public static String randomStr(int n) {
        StringBuilder s = new StringBuilder();
        char[] stringArray = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i',
                'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u',
                'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6',
                '7', '8', '9'};
        for (int i = 0; i < n; i++) {
            char num = stringArray[random.nextInt(stringArray.length)];
            s.append(num);
        }
        return s.toString();
    }

    /**
     * 随机获取 [min, max] 范围内的随机整数
     * eg: [1, 3] => 1, 2, 3
     * ps: min为0的时候会计算会少1，如：[0, 3] => 0, 1, 2
     * @return random int
     */
    public static int getRandom(int min, int max){
        return random.nextInt(max) % (max - min + 1) + min;
    }

    /**
     * 随机获取long数值
     * @return
     */
    public static long getRandomLong() {
        return Math.abs(random.nextLong());
    }

    /**
     * byte[] => string
     * @param src
     * @return
     */
    public static String bytes2Hex(byte[] src){
        if (src == null || src.length <= 0) {
            return null;
        }

        StringBuilder stringBuilder = new StringBuilder("");
        for (int i = 0; i < src.length; i++) {
            // 之所以用byte和0xff相与，是因为int是32位，与0xff相与后就舍弃前面的24位，只保留后8位
            String str = Integer.toHexString(src[i] & 0xff);
            if (str.length() < 2) { // 不足两位要补0
                stringBuilder.append(0);
            }
            stringBuilder.append(str);
        }
        return stringBuilder.toString();
    }

    /**
     * URL编码
     * @param src
     * @return
     */
    public static String urlEncode(String src) {
        try {
            return URLEncoder.encode(src, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * URL解码
     * @param src
     * @return
     */
    public static String urlDecode(String src) {
        try {
            return URLEncoder.encode(src, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
            return null;
        }
    }

}
