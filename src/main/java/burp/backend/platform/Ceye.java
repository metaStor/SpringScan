package burp.backend.platform;

import burp.*;
import burp.backend.IBackend;
import burp.util.Utils;

import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.net.URL;

/**
 * @author : metaStor
 * @date : Created 2022/4/9 2:10 AM
 * @description:
 */
public class Ceye implements IBackend {

    private IBurpExtenderCallbacks callbacks;
    private BurpExtender burpExtender;
    private IExtensionHelpers helpers;
    private PrintWriter stdout;
    private PrintWriter stderr;

    private String platform = "http://api.ceye.io/v1/records/";
    private String token;  // xxxxxxxxxxxxxxxxxxxx
    private String api;  // xxxxxx.ceye.io
    private String rootDomain = "";

    public Ceye(IBurpExtenderCallbacks callbacks, BurpExtender burpExtender) {
        // init
        this.callbacks = callbacks;
        this.helpers = this.callbacks.getHelpers();
        this.burpExtender = burpExtender;
        this.helpers = this.callbacks.getHelpers();
        this.stdout = new PrintWriter(this.callbacks.getStdout());
        this.stderr = new PrintWriter(this.callbacks.getStderr());
        // init token and api identify
        this.token = this.burpExtender.tags.getSettingUi().getTokenField().trim();
        this.api = this.burpExtender.tags.getSettingUi().getApiField().trim();
    }
    @Override
    public String getPlatform() {
        return this.platform;
    }

    @Override
    public String getRootDomain() {
        return this.rootDomain;
    }

    /**
     * `randomStr`.xxxxxx.ceye.io
     * @return
     */
    @Override
    public String generatePayload() {
        this.rootDomain = Utils.randomStr(5);  // filter max length is 20
        return this.rootDomain + "." + this.api;
    }

    @Override
    public boolean getState() {
        return true;
    }

    /**
     * 直接从平台取，不用每次都flushCache
     * @param payload => @this.generatePayload()
     * @return  true/false
     */
    @Override
    public boolean checkResult(String payload) {
        // load token and api identify
        this.token = this.burpExtender.tags.getSettingUi().getTokenField().trim();
        this.api = this.burpExtender.tags.getSettingUi().getApiField().trim();
        // ready request for flush
        String url = this.platform + "?token=" + this.token + "&type=dns&filter=" + payload;
        try {
            byte[] rawRequest = this.helpers.buildHttpRequest(new URL(url));
            IHttpService service = this.helpers.buildHttpService("api.ceye.io", 80, "HTTP");
            IHttpRequestResponse requestResponse = this.callbacks.makeHttpRequest(service, rawRequest);
            byte[] rawResponse = requestResponse.getResponse();
            IResponseInfo responseInfo = this.helpers.analyzeResponse(rawResponse);
            String body = new String(rawResponse).substring(responseInfo.getBodyOffset()).trim().toLowerCase();
            // 是否有回连记录
            return (body.contains(payload));
        } catch (MalformedURLException e) {
            e.printStackTrace();
            this.stderr.println(e.getMessage());
            return false;
        }
    }

    @Override
    public boolean flushCache() {
        return true;
    }

    @Override
    public void close() {

    }

}
