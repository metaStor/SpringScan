package burp.backend.platform;

import burp.IBurpCollaboratorClientContext;
import burp.IBurpCollaboratorInteraction;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.backend.IBackend;

import java.util.List;

/**
 * @author : metaStor
 * @date : Created 2022/4/8
 * @description: BurpCollaboratorClient 使用自带接口实现
 * */
public class BurpCollaboratorClient implements IBackend {

    private final String platform = "burpcollaborator.net";
    private String rootDomain = "";
    private IBurpCollaboratorClientContext clientContext;
    private IExtensionHelpers helpers;

    // 初始化server
    public BurpCollaboratorClient(IBurpExtenderCallbacks callbacks) {
        this.helpers = callbacks.getHelpers();
        this.clientContext = callbacks.createBurpCollaboratorClientContext();
        // 初始化域名
        this.rootDomain = this.clientContext.generatePayload(true);
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
        return this.rootDomain;
    }

    /**
     * 生成 payload
     * @return xxxxxx.burpcollaborator.net
     */
    @Override
    public String generatePayload() {
        return this.rootDomain;
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
        // 截取前面五个随机字符
        String randomChar = domain.split("\\." + this.rootDomain)[0];
        // fetch 回连结果
        List<IBurpCollaboratorInteraction> res = clientContext.fetchCollaboratorInteractionsFor(this.rootDomain);
        for (IBurpCollaboratorInteraction val : res) {
            if (this.helpers.bytesToString(this.helpers.base64Decode(val.getProperty("raw_query"))).contains(randomChar)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public boolean flushCache() {
        return true;
    }

    @Override
    public void close() {

    }

}
