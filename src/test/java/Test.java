import burp.util.YamlUtil;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @author : metaStor
 * @date : Created 2022/4/6 10:05 PM
 * @description:
 */
public class Test {

    public static void main(String[] args) throws InterruptedException, IOException {
//        String url = String.valueOf("http://localhost:8088/x?test=1").split("\\?")[0];  // 获取?之前的url
//        String url2 = String.valueOf("http://localhost:8080/").split("\\?")[0];  // 获取?之前的url
//        System.out.println(url);
//        System.out.println(url2);
//        String root = "u3yffici9aabcqyfm0gv616ih9nzbo.burpcollaborator.net";
//        String test = "12345." + root;
//        System.out.println(test.split("\\." + root)[0]);
        /*
        // 设置块级显示
        DumperOptions options  = new DumperOptions();
        options.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
        options.setIndentWithIndicator(true);
        options.setIndicatorIndent(2);
        Representer representer = new Representer(options);
        Yaml yaml = new Yaml(representer, options);
        FileWriter writer = new FileWriter("test.yml");
        yaml.dump(map, writer);
        */

        Map<String, Object> data = new HashMap<>();
        List<String> list = new ArrayList<>();
        list.add("xxxxxx.ceye.io");
        list.add("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");

        data.put("isEnable", true);
        data.put("isErrorCheck", true);
        data.put("isReverseCheck", true);
        data.put("backendPlat", "Dnslog");
        data.put("ceyes", list);

        System.out.println(YamlUtil.saveYaml(data, "test.yml"));

        Map<String, Object> ress = YamlUtil.loadYaml("test.yml");
        for (Map.Entry<String, Object> entry: ress.entrySet()) {
            System.out.println(entry.getKey() + "\t: \t" + entry.getValue());
        }
    }
}
