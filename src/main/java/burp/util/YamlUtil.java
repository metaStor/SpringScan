package burp.util;

import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.Yaml;

import java.io.*;
import java.util.Map;

/**
 * @author : metaStor
 * @date : Created 2023/11/12 1:38 AM
 * @description:
 */
public class YamlUtil {

    public static Yaml newYaml() {
        // 设置块级显示
        DumperOptions options  = new DumperOptions();
        options.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
        options.setIndentWithIndicator(true);
        options.setIndicatorIndent(2);
        return new Yaml(options);
    }

    public static boolean saveYaml(Map<String, Object> data, String filename) {
        try {
            newYaml().dump(data, new FileWriter(filename));
            return true;
        } catch (IOException e) {
            e.printStackTrace();
        }
        return false;
    }

    public static Map<String, Object> loadYaml(String filename) {
        try {
            return newYaml().load(new FileInputStream(filename));
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
        return null;
    }
}
