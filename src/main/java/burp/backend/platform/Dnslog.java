package burp.backend.platform;

import burp.*;
import burp.backend.IBackend;
import burp.util.Utils;

import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.*;

/**
 * @author : metaStor
 * @date : Created 2022/4/8
 * @description: Dnslog
 * */
public class Dnslog implements IBackend {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private PrintWriter stdout;
    private PrintWriter stderr;

    private ICookie iCookie;
    private String platform = "http://www.dnslog.cn/";
    private String rootDomain = "";
    private String resultCache = "";

    public Dnslog(IBurpExtenderCallbacks callbacks) {
        // init
        this.callbacks = callbacks;
        this.helpers = this.callbacks.getHelpers();
        this.stdout = new PrintWriter(this.callbacks.getStdout());
        this.stderr = new PrintWriter(this.callbacks.getStderr());
        this.initDomain();
    }

    /**
     * 获取 dnslog 子域名
     */
    private void initDomain() {
        String url = this.platform + "getdomain.php?t=0." + Utils.getRandomLong();
        try {
            byte[] rawRequest = this.helpers.buildHttpRequest(new URL(url));
            IHttpService service = this.helpers.buildHttpService("www.dnslog.cn", 80, "HTTP");
            IHttpRequestResponse requestResponse = this.callbacks.makeHttpRequest(service, rawRequest);
            byte[] rawResponse = requestResponse.getResponse();
            IResponseInfo responseInfo = this.helpers.analyzeResponse(rawResponse);
            // 获取响应包body内容 => 即dnslog的子域名
            this.rootDomain = new String(rawResponse).substring(responseInfo.getBodyOffset()).trim();
            // 提取cookie
            List<ICookie> cookies = responseInfo.getCookies();
            for (ICookie cookie : cookies) {
                if (cookie.getName().equals("PHPSESSID")) {
                    this.iCookie = cookie;
                }
            }
            this.stdout.println("[*] Get domain: " + this.rootDomain);
        } catch (MalformedURLException e) {
            e.printStackTrace();
            this.stdout.println("[-] Fail to get domain");
            this.stderr.println(e.getMessage());
        }
    }

    @Override
    public String getPlatform() {
        return this.platform;
    }

    /**
     * 子域名
     * @return xxx.dnslog.cn
     */
    @Override
    public String getRootDomain() {
        return this.rootDomain;
    }

    /**
     * 功能与 @getRootDomain() 重复
     * @return xxx.dnslog.cn
     */
    @Override
    public String generatePayload() {
        return this.rootDomain;
    }

    @Override
    public boolean getState() {
        return !this.rootDomain.equals("");
    }

    @Override
    public boolean checkResult(String domain) {
        this.flushCache();
        return this.resultCache.contains(domain.toLowerCase());
    }

    /**
     * 持续向dnslog请求是否有回连数据
     * @return 结果保存到 @this.resultCache
     */
    @Override
    public boolean flushCache() {
        String url = this.platform + "getrecords.php?t=0." + Utils.getRandomLong();
        try {
            byte[] rawRequest = this.helpers.buildHttpRequest(new URL(url));
            IHttpService service = this.helpers.buildHttpService("www.dnslog.cn", 80, "HTTP");
            // 加入cookie
            IParameter cookieParam = this.helpers.buildParameter(this.iCookie.getName(), this.iCookie.getValue(), IParameter.PARAM_COOKIE);
            byte[] newRawRequest = this.helpers.updateParameter(rawRequest, cookieParam);
            IHttpRequestResponse requestResponse = this.callbacks.makeHttpRequest(service, newRawRequest);
            byte[] rawResponse = requestResponse.getResponse();
            IResponseInfo responseInfo = this.helpers.analyzeResponse(rawResponse);
            // 获取响应包body内容
            this.resultCache = new String(rawResponse).substring(responseInfo.getBodyOffset()).trim().toLowerCase();
        } catch (MalformedURLException e) {
            e.printStackTrace();
            this.stderr.println(e.getMessage());
        }
        return true;
    }

    @Override
    public void close() {

    }

}