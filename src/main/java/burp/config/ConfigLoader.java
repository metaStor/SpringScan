package burp.config;

import burp.BurpExtender;
import burp.util.YamlUtil;

import java.io.File;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @author : metaStor
 * @date : Created 2023/11/12 1:33 AM
 * @description:
 */
public class ConfigLoader {

    private static final String configPath = determineConfigPath();
    private static final String configFileName = Paths.get(configPath, "config.yml").toString();


    public ConfigLoader() {
        // init
        File configPathFile = new File(configPath);
        if (!(configPathFile.exists() && configPathFile.isDirectory())) {
            configPathFile.mkdirs();
        }
        File configFile = new File(configFileName);
        if (!(configFile.exists() && configFile.isFile())) {
            defaultConfigFile();
        }
    }

    /**
     * 获取当前jar包目录
     */
    private static String determineConfigPath() {
        // Jar包所在目录
        String jarPath = BurpExtender.callbacks.getExtensionFilename();
        String jarDirectory = new File(jarPath).getParent();
        return String.format("%s/config", jarDirectory);
    }

    /**
     * 初始化默认配置文件
     */
    private static void defaultConfigFile() {
        Map<String, Object> data = new HashMap<>();
        List<String> list = new ArrayList<>();

        list.add("xxxxxx.ceye.io");
        list.add("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");

        data.put("isEnable", true);
        data.put("isErrorCheck", true);
        data.put("isReverseCheck", true);
        data.put("backendPlat", "Dnslog");
        data.put("ceyes", list);

        YamlUtil.saveYaml(data, configFileName);
    }

    /**
     * 保存配置文件
     */
    public static void saveConfig(Map<String, Object> map) {
        YamlUtil.saveYaml(map, configFileName);
    }

    /**
     * 读取配置文件
     */
    public static Map<String, Object> loadConfig() {
        return YamlUtil.loadYaml(configFileName);
    }
}
