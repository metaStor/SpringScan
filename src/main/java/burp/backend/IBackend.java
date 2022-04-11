package burp.backend;

/**
 * @author : metaStor
 * @date : Created 2022/4/8
 * @description: 回连平台实现接口
 * */
public interface IBackend {

    String getPlatform();

    String getRootDomain();

    String generatePayload();

    boolean getState();

    boolean checkResult(String payload);

    boolean flushCache();

    void close();

}
