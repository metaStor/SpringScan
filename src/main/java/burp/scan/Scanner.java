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
    private final Set<String> allScan = new HashSet<>();

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
        this.pocs = Utils.getPocs(new Integer[]{1, 2, 3});
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

        List<IScanIssue> issues = new ArrayList<>();
        IRequestInfo requestInfo = this.helpers.analyzeRequest(iHttpRequestResponse);
        IResponseInfo responseInfo = this.helpers.analyzeResponse(iHttpRequestResponse.getResponse());
        if (responseInfo.getStatusCode() == 404) return null;  // 跳过404
        String url = String.valueOf(requestInfo.getUrl());
        String url_md5 = normalized(requestInfo);
        if (!this.isStaticFile(url) && !this.isChecked(url_md5)) {  // 跳过静态文件和同类uri
            boolean isVul = false;
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
                IScanIssue errorIssue = this.errorScan(iHttpRequestResponse);
                if (errorIssue != null) {
                    isVul = true;
                    this.burpExtender.stdout.println(String.format("[+] ErrorChecker found %s Vul!", url));
                    issues.add(errorIssue);
                    // 扫描结果输出到UI
                    this.burpExtender.tags.getScannerUi().save(
                            id,
                            "ErrorCheck",
                            requestInfo.getMethod(),  // this.burpExtender.helpers.analyzeRequest(errorIssue.getHttpMessages()[0].getRequest()).getMethod()
                            String.valueOf(requestInfo.getUrl()),  // String.valueOf(this.burpExtender.helpers.analyzeRequest(errorIssue.getHttpMessages()[0].getRequest()).getUrl());
                            String.valueOf(this.helpers.analyzeResponse(iHttpRequestResponse.getResponse()).getStatusCode()),
                            "[+] SpringCore RCE",
                            errorIssue.getHttpMessages()[0]
                    );
                }
                // 已扫描uri的集合
                this.allScan.add(url_md5);
            }
            /**
             * 回连扫描
             */
            if (this.burpExtender.tags.getSettingUi().isReverseCheck()) {
                IScanIssue reverseIssue = this.reverseScan(iHttpRequestResponse);
                if (reverseIssue != null) {
                    isVul = true;
                    this.burpExtender.stdout.println(String.format("[+] ReverseChecker found %s Vul!", url));
                    issues.add(reverseIssue);
                    // 扫描结果输出到UI
                    this.burpExtender.tags.getScannerUi().save(
                            id,
                            "ReverseCheck",
                            requestInfo.getMethod(),  // this.burpExtender.helpers.analyzeRequest(errorIssue.getHttpMessages()[0].getRequest()).getMethod()
                            String.valueOf(requestInfo.getUrl()),  // String.valueOf(this.burpExtender.helpers.analyzeRequest(errorIssue.getHttpMessages()[0].getRequest()).getUrl());
                            String.valueOf(this.helpers.analyzeResponse(iHttpRequestResponse.getResponse()).getStatusCode()),
                            "[+] SpringCore RCE",
                            reverseIssue.getHttpMessages()[0]
                    );
                }
                // 已扫描uri的集合
                this.allScan.add(url_md5);
            }
            // 不存在漏洞, 更新UI
            if (!isVul) {
                this.burpExtender.tags.getScannerUi().save(
                        id,
                        "ALL",
                        requestInfo.getMethod(),
                        String.valueOf(requestInfo.getUrl()),
                        String.valueOf(this.helpers.analyzeResponse(iHttpRequestResponse.getResponse()).getStatusCode()),
                        "[-] Not Found SpringRCE",
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
                return new SpringCoreIssue(
                        requestInfo.getUrl(),
                        "SpringCoreRCE",
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
                return new SpringCoreIssue(
                        requestInfo.getUrl(),
                        "SpringCoreRCE",
                        0,
                        "High",
                        "Certain",
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
            this.burpExtender.stdout.println("[*] Reverse Checking " + requestInfo.getUrl().toString() + " ...");
            // 5min内查看是否回连
            for (int i = 0; i < 10; i++) {
//                this.burpExtender.stdout.println("[-] No." + i + " Checking " + requestInfo.getUrl().toString());
                if (this.backend.checkResult(payload)) {
                    return new SpringCoreIssue(
                            requestInfo.getUrl(),
                            "SpringCoreRCE",
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
     * 排除正常响应码: 200, 404
     * @param status_code
     * @return
     */
    private boolean isErrorStatusCode(int status_code) {
        return Arrays.stream(new Integer[]{200, 404}).noneMatch(e -> e == status_code);
    }

}
