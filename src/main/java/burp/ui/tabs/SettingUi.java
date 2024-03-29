package burp.ui.tabs;

import burp.IBurpExtenderCallbacks;
import burp.config.ConfigLoader;
import burp.util.UIUtil;
import burp.util.YamlUtil;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @author ：metaStor
 * @date ：Created 2022/4/6 7:27 PM
 * @description： 设置扫描方法：报错检测、反连检测(burpCollaborator/dnslog/ceye)
 *
 * TODO
 * 自定义回连平台
 */
public class SettingUi {

    public enum Backends {
        BurpCollaborator, Dnslog, Ceye
    }

    private IBurpExtenderCallbacks callbacks;

    // ui
    private JTabbedPane tabs;
    private JTabbedPane reverseTabs;
    private JCheckBox enableCheckBox;
    private JCheckBox errorCheckBox;
    private JCheckBox reverseCheckBox;
    private JLabel enableLabel;
    private JLabel checkLabel;
    private JLabel reverseLabel;
    private JPanel backendUI;
    private JComboBox<String> backendSelector;
    private JTextField apiInput;
    private JTextField tokenInput;
    private JButton SaveButton;  // save all config



    public SettingUi(IBurpExtenderCallbacks callbacks, JTabbedPane tabs) {
        this.callbacks = callbacks;
        this.tabs = tabs;
        this.initUI();
        this.tabs.addTab("Setting", this.backendUI);
    }

    private void initUI() {
        this.backendUI = new JPanel();
        this.backendUI.setAlignmentX(0.0f);
        this.backendUI.setBorder(new EmptyBorder(10, 10, 10, 10));
        this.backendUI.setLayout(new BoxLayout(this.backendUI, BoxLayout.Y_AXIS));  // 垂直对齐

        this.enableLabel = new JLabel("插件:     ");
        this.checkLabel = new JLabel("检测方法:     ");
        this.reverseLabel = new JLabel("回连方法:     ");
        this.enableCheckBox = new JCheckBox("启动", true);
        this.errorCheckBox = new JCheckBox("回显检测   ", true);
        this.reverseCheckBox = new JCheckBox("回连检测", true);

        this.SaveButton = new JButton("SaveConfig");

        this.enableLabel.setForeground(new Color(255, 89, 18));
        this.enableLabel.setFont(new Font("Serif", Font.PLAIN, this.enableLabel.getFont().getSize() + 2));

        this.checkLabel.setForeground(new Color(255, 89, 18));
        this.checkLabel.setFont(new Font("Serif", Font.PLAIN, this.checkLabel.getFont().getSize() + 2));

        this.reverseLabel.setForeground(new Color(255, 89, 18));
        this.reverseLabel.setFont(new Font("Serif", Font.PLAIN, this.reverseLabel.getFont().getSize() + 2));

        this.backendSelector = new JComboBox<String>(this.getSelectors());
        this.backendSelector.setSelectedIndex(2);
        this.backendSelector.setMaximumSize(this.backendSelector.getPreferredSize());

        this.reverseTabs = new JTabbedPane();
        this.reverseTabs.addTab("Ceye", this.getCeyePanel());

        this.SaveButton.addActionListener(this::saveActionListener);

        JPanel runPanel = UIUtil.GetXPanel();
        runPanel.add(this.enableLabel);
        runPanel.add(this.enableCheckBox);

        JPanel checkPanel = UIUtil.GetXPanel();
        checkPanel.add(this.checkLabel);
        checkPanel.add(this.errorCheckBox);
        checkPanel.add(this.reverseCheckBox);

        JPanel reversePanel = UIUtil.GetXPanel();
        reversePanel.add(this.reverseLabel);
        reversePanel.add(this.backendSelector);
        reversePanel.add(new JLabel("  "));
        reversePanel.add(this.SaveButton);

        JPanel settingPanel = UIUtil.GetYPanel();
        settingPanel.add(runPanel);
        settingPanel.add(checkPanel);
        settingPanel.add(reversePanel);

        JPanel reverseInfoPanel = UIUtil.GetXPanel();
        reverseInfoPanel.add(this.reverseTabs);

        this.backendUI.add(settingPanel);
        this.backendUI.add(reverseInfoPanel);

        // load config
        Map<String, Object> configs = ConfigLoader.loadConfig();
        List<String> ceyes = (List<String>) configs.get("ceyes");
        this.enableCheckBox.setSelected((Boolean) configs.get("isEnable"));
        this.errorCheckBox.setSelected((Boolean) configs.get("isErrorCheck"));
        this.reverseCheckBox.setSelected((Boolean) configs.get("isReverseCheck"));
        this.backendSelector.setSelectedItem((String) configs.get("backendPlat"));
        this.apiInput.setText(ceyes.get(0));
        this.tokenInput.setText(ceyes.get(1));
    }


    private JPanel getCeyePanel() {
        JPanel jPanel = UIUtil.GetYPanel();
        JPanel apiPanel = UIUtil.GetXPanel();
        JPanel tokenPanel = UIUtil.GetXPanel();

        apiInput = new JTextField("xxxxxx.ceye.io", 50);
        tokenInput = new JTextField("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", 50);

        apiInput.setMaximumSize(apiInput.getPreferredSize());
        tokenInput.setMaximumSize(tokenInput.getPreferredSize());

        apiPanel.add(new JLabel("Identifier:     "));
        apiPanel.add(apiInput);

        tokenPanel.add(new JLabel("API Token:   "));
        tokenPanel.add(tokenInput);

        jPanel.add(apiPanel);
        jPanel.add(tokenPanel);
        return jPanel;
    }

    private String[] getSelectors() {
        ArrayList<String> selectors = new ArrayList<String>();
        for (Backends backend: Backends.values()) {
            selectors.add(backend.name().trim());
        }
        return selectors.toArray(new String[selectors.size()]);
    }

    private void saveActionListener(ActionEvent actionEvent) {
        Map<String, Object> data = new HashMap<>();
        List<String> ceyes = new ArrayList<>();

        ceyes.add(this.apiInput.getText());
        ceyes.add(this.tokenInput.getText());

        data.put("isEnable", this.enableCheckBox.isSelected());
        data.put("isErrorCheck", this.errorCheckBox.isSelected());
        data.put("isReverseCheck", this.reverseCheckBox.isSelected());
        data.put("backendPlat", this.backendSelector.getItemAt(this.backendSelector.getSelectedIndex()));
        data.put("ceyes", ceyes);

        ConfigLoader.saveConfig(data);

        JOptionPane.showMessageDialog(null, "保存成功");
    }

    /**
     * 插件是否开启状态
     * @return true/false
     */
    public boolean isEnable() {
        return this.enableCheckBox.isSelected();
    }

    /**
     * 是否开启报错检测
     * @return true/false
     */
    public boolean isErrorCheck() {
        return this.errorCheckBox.isSelected();
    }

    /**
     * 是否开启回连检测
     * @return true/false
     */
    public boolean isReverseCheck() {
        return this.reverseCheckBox.isSelected();
    }

    /**
     * 返回选择到回连平台
     * @return Dnslog/BurpCollaboratorClient/Ceye
     */
    public Backends getBackendPlatform() {
        return Backends.valueOf(this.backendSelector.getSelectedItem().toString());
    }

    /**
     * 获取 Ceye Api 地址
     * @return xxxxxx.ceye.io
     */
    public String getApiField() {
        return this.apiInput.getText().trim().toLowerCase();
    }

    /**
     * 获取 Ceye Token
     * @return xxxxxxxxxxxxxxxxx
     */
    public String getTokenField() {
        return this.tokenInput.getText().trim().toLowerCase();
    }
}
