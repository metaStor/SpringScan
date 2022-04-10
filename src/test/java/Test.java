import burp.payload.IPoc;
import burp.payload.pocs.POC3;
import burp.util.Utils;

/**
 * @author : metaStor
 * @date : Created 2022/4/6 10:05 PM
 * @description:
 */
public class Test {

    public static void main(String[] args) throws InterruptedException {
        String url = String.valueOf("http://localhost:8088/x?test=1").split("\\?")[0];  // 获取?之前的url
        String url2 = String.valueOf("http://localhost:8080/").split("\\?")[0];  // 获取?之前的url
        System.out.println(url);
        System.out.println(url2);
    }
}
