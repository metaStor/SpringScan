package burp.payload.pocs;

import burp.payload.IPoc;

/**
 * @author : metaStor
 * @date : Created 2022/4/7
 * @description: 报错检测
 * POC:
 * class.module.classLoader[xxx]=xxx => status_code: 400
 * url（正常请求） => 页面正常
 * */
public class POC2 implements IPoc {

    public POC2() {    }

    @Override
    public String genPoc() {
        return "class.module.classLoader[%s]=%s";
    }
}
