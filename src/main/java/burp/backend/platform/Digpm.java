package burp.backend.platform;

import burp.*;
import burp.backend.IBackend;
import burp.util.Utils;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;

import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.List;

/**
 * @author : metaStor
 * @date : Created 2022/4/12 11:40 PM
 * @description: dig.pm 回连平台
 */
public class Digpm implements IBackend {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private PrintWriter stdout;
    private PrintWriter stderr;
    private IHttpService service;

    private String platform = "https://dig.pm/";
    private List<String> domains;
    // domain = key.rootDomain，由@generatePayload()生成
    private String rootDomain = "";
    private String domain = "";
    private String key = "";
    private String token = "";  // 用于fetch结果
    private String resultCache = "";

    public Digpm(IBurpExtenderCallbacks callbacks) {
        // init
        this.callbacks = callbacks;
        this.helpers = this.callbacks.getHelpers();
        this.stdout = new PrintWriter(this.callbacks.getStdout());
        this.stderr = new PrintWriter(this.callbacks.getStderr());
        this.service = this.helpers.buildHttpService("dig.pm", 443, true);
        this.initDomain();
    }

    private void initDomain() {
        this.getDomains();
        // 随机选择一个dnslog域名
        this.rootDomain = this.domains.get(Utils.getRandom(1, this.domains.size()) - 1);
        this.stdout.println("[*] Choose domain: " + this.rootDomain);
        this.stdout.println("[*] Get domain: " + this.generatePayload());
    }

    /**
     * 获取平台可用的dnslog_doamins
     * @return
     */
    private void getDomains() {
        try {
            byte[] rawRequest = this.helpers.buildHttpRequest(new URL(this.platform + "get_domain"));
            IHttpRequestResponse requestResponse = this.callbacks.makeHttpRequest(this.service, rawRequest);
            byte[] rawResponse = requestResponse.getResponse();
            IResponseInfo responseInfo = this.helpers.analyzeResponse(rawResponse);
            // 获取响应包body内容: ["xxx", "xxx"]
            String response = new String(rawResponse).substring(responseInfo.getBodyOffset()).trim();
            // string to json
            this.domains = JSONArray.parseArray(response, String.class);
            this.stdout.println("[*] Get domains: " + this.domains.toString());
        } catch (MalformedURLException e) {
            e.printStackTrace();
            this.stdout.println("[-] Fail to get domains");
            this.stderr.println(e.getMessage());
        }
    }

    @Override
    public String getPlatform() {
        return this.platform;
    }

    /**
     * 获取dnslog域名
     * @return eg: dns.bypass.eu.org.
     */
    @Override
    public String getRootDomain() {
        return this.rootDomain;
    }

    /**
     * 根据随机选取的rootDomain生成domain、key、token
     * @return xxxxxxxx.`rootDomain`
     */
    @Override
    public String generatePayload() {
        try {
            IParameter param = this.helpers.buildParameter("mainDomain", this.rootDomain, IParameter.PARAM_BODY);
            byte[] rawRequest = this.helpers.buildHttpRequest(new URL(this.platform + "get_sub_domain"));
            rawRequest = this.helpers.toggleRequestMethod(rawRequest);  // GET to POST
            rawRequest = this.helpers.addParameter(rawRequest, param);  // add param
            IHttpRequestResponse requestResponse = this.callbacks.makeHttpRequest(this.service, rawRequest);
            byte[] rawResponse = requestResponse.getResponse();
            IResponseInfo responseInfo = this.helpers.analyzeResponse(rawResponse);
            // 获取响应包body内容: {"key": "value"}
            String response = new String(rawResponse).substring(responseInfo.getBodyOffset()).trim();
            this.stdout.println("[*] Get subdomain: " + response);
            // to Json
            JSONObject domainJson = JSONObject.parseObject(response);
            this.domain = domainJson.get("fullDomain").toString().trim();
            this.key = domainJson.get("subDomain").toString().trim();
            this.token = domainJson.get("token").toString().trim();
            return this.domain;
        } catch (MalformedURLException e) {
            e.printStackTrace();
            this.stdout.println("[-] Fail to generate subdomain");
            this.stderr.println(e.getMessage());
        }
        return null;
    }

    @Override
    public boolean getState() {
        return !this.rootDomain.equals("");
    }

    /**
     * fetch结果中是否包含pyalod
     * @param payload
     * @return true/false
     *
     * TODO
     * 有多重验证，需要发两个包才能get_results，暂未实现
     */
    @Override
    public boolean checkResult(String payload) {
        try {
            IParameter param1 = this.helpers.buildParameter("mainDomain", this.rootDomain, IParameter.PARAM_BODY);
            IParameter param2 = this.helpers.buildParameter("token", this.token, IParameter.PARAM_BODY);
            IParameter param3 = this.helpers.buildParameter("subDomain", this.token, IParameter.PARAM_BODY);
            byte[] rawRequest = this.helpers.buildHttpRequest(new URL(platform + "get_results"));
            rawRequest = this.helpers.toggleRequestMethod(rawRequest);  // GET to POST
            rawRequest = this.helpers.addParameter(rawRequest, param1);
            rawRequest = this.helpers.addParameter(rawRequest, param2);
            rawRequest = this.helpers.addParameter(rawRequest, param3);
            IHttpRequestResponse requestResponse = this.callbacks.makeHttpRequest(this.service, rawRequest);
            byte[] rawResponse = requestResponse.getResponse();
            IResponseInfo responseInfo = this.helpers.analyzeResponse(rawResponse);
            // 获取响应包body内容
            String response = new String(rawResponse).substring(responseInfo.getBodyOffset()).trim();
            this.stdout.println(response.contains(payload));
            return response.contains(payload);
        } catch (MalformedURLException e) {
            e.printStackTrace();
            this.stdout.println("[-] Fail to fetch result");
            this.stderr.println(e.getMessage());
        }
        return false;
    }

    @Override
    public boolean flushCache() {
        return false;
    }

    @Override
    public void close() {

    }
}
