package burp.backend.platform;

import burp.IBurpCollaboratorClientContext;
import burp.IBurpExtenderCallbacks;
import burp.backend.IBackend;
import burp.util.Utils;

/**
 * @author : metaStor
 * @date : Created 2022/4/8
 * @description: BurpCollaboratorClient 使用自带接口实现
 * */
public class BurpCollaboratorClient implements IBackend {

    private final String platform = "burpcollaborator.net";
    private IBurpCollaboratorClientContext clientContext;

    // 初始化server
    public BurpCollaboratorClient(IBurpExtenderCallbacks callbacks) {
        this.clientContext = callbacks.createBurpCollaboratorClientContext();
    }

    @Override
    public String getPlatform() {
        return this.platform;
    }

    /**
     * 获取dns地址，具体实现在 @generatePayload()
     * @return
     */
    @Override
    public String getRootDomain() {
        return "";
    }

    /**
     * 生成 payload
     * @return xxxxxx.burpcollaborator.net
     */
    @Override
    public String generatePayload() {
        return this.clientContext.generatePayload(true);
    }

    @Override
    public boolean getState() {
        return true;
    }

    /**
     * 根据 payload 查看是否有回连
     * @param domain: xxxxxx.burpcollaborator.net
     * @return true/false
     */
    @Override
    public boolean checkResult(String domain) {
        return this.clientContext.fetchCollaboratorInteractionsFor(domain).size() > 0;
    }

    @Override
    public boolean flushCache() {
        return true;
    }

}
