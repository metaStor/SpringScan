package burp.backend.platform;

import burp.*;
import burp.backend.IBackend;
import burp.util.RandomHeaders;
import burp.util.Utils;
import okhttp3.*;

import java.io.PrintWriter;
import java.util.*;
import java.util.concurrent.TimeUnit;

/**
 * @author : metaStor
 * @date : Created 2022/4/8
 * @description: Dnslog (用okhttp3重做)
 * */
public class Dnslog implements IBackend {

    private IBurpExtenderCallbacks callbacks;
    private PrintWriter stdout;
    private PrintWriter stderr;

    private String platform = "http://www.dnslog.cn";
    private String rootDomain = "";
    private String resultCache = "";

    private Timer timer;

    OkHttpClient client = new OkHttpClient().newBuilder().cookieJar(new CookieJar() {
                private final HashMap<String, List<Cookie>> cookieStore = new HashMap<>();

                @Override
                public void saveFromResponse(HttpUrl url, List<Cookie> cookies) {
                    cookieStore.put(url.host(), cookies);
                }

                @Override
                public List<Cookie> loadForRequest(HttpUrl url) {
                    List<Cookie> cookies = cookieStore.get(url.host());
                    return cookies != null ? cookies : new ArrayList<Cookie>();
                }
            }).connectTimeout(50, TimeUnit.SECONDS).
            callTimeout(50, TimeUnit.SECONDS).
            readTimeout(3, TimeUnit.MINUTES).build();

    public Dnslog(IBurpExtenderCallbacks callbacks) {
        // init
        this.callbacks = callbacks;
        this.stdout = new PrintWriter(this.callbacks.getStdout());
        this.stderr = new PrintWriter(this.callbacks.getStderr());
        this.timer = new Timer();
        this.initDomain();
    }

    /**
     * 获取 dnslog 子域名
     */
    private void initDomain() {
        try {
//            this.callbacks.printOutput("get domain...");
            Response resp = client.newCall(GetDefaultRequest(this.platform + "/getdomain.php?t=0." + Utils.getRandomLong()).build()).execute();
            rootDomain = resp.body().string();
//            this.callbacks.printOutput(String.format("[*] Domain: %s", rootDomain));
            startSessionHeartbeat();
        } catch (Exception ex) {
            this.callbacks.printError("[-] initDomain failed: " + ex.getMessage());
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
        return Utils.randomStr(5) + "." + this.rootDomain;
    }

    @Override
    public boolean getState() {
        return !this.rootDomain.equals("");
    }

    @Override
    public boolean checkResult(String domain) {
        return this.resultCache.contains(domain.toLowerCase());
    }

    /**
     * 持续向dnslog请求是否有回连数据
     * @return 结果保存到 @this.resultCache
     */
    @Override
    public boolean flushCache() {
        try {
            Response resp = client.newCall(GetDefaultRequest(this.platform + "/getrecords.php?t=0." + Utils.getRandomLong()).build()).execute();
            this.resultCache = resp.body().string().toLowerCase();
//            this.callbacks.printOutput(String.format("Got Dnslog Result OK!: %s", this.resultCache));
            return true;
        } catch (Exception ex) {
            this.callbacks.printOutput(String.format("[-] Get Dnslog Result Failed!: %s", ex.getMessage()));
            return false;
        }
    }

    private void startSessionHeartbeat() {
        timer.schedule(new TimerTask() {
            @Override
            public void run() {
                flushCache();
            }
        }, 0, 10 * 1000); // 10s
    }

    private Request.Builder GetDefaultRequest(String url) {
        CacheControl NoCache = new CacheControl.Builder().noCache().noStore().build();
        Request.Builder requestBuilder = new Request.Builder()
                .url(url);
        requestBuilder.header("User-Agent", RandomHeaders.randomHeader());
        return requestBuilder.cacheControl(NoCache);
    }

    @Override
    public void close() {
        this.timer.cancel();
    }

}
