package burp.util;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.payload.IPoc;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

/**
 * @author : metaStor
 * @date : Created 2022/4/7
 * @description: 工具类
 * */
public class Utils {

    public static Random random = new Random();

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
}
