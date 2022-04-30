package burp.ui.menu;

import burp.*;
import burp.scan.Scanner;

import javax.swing.*;
import java.util.ArrayList;
import java.util.List;

/**
 * @author : metaStor
 * @date : Created 2022/4/30 5:24 PM
 * @description: 主动扫描Menu
 * @TODO: target中都没有记录，可在tabUI中查看扫描情况
 */
public class Menu implements IContextMenuFactory {

    private BurpExtender burpExtender;
    private Scanner scanner;

    public Menu(BurpExtender burpExtender, Scanner scanner) {
        this.burpExtender = burpExtender;
        this.scanner = scanner;
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation iContextMenuInvocation) {
        List<JMenuItem> menuItems = new ArrayList<JMenuItem>();
        JMenuItem sendItem = new JMenuItem("doScan");
        // Override ActionListener
        sendItem.addActionListener(e -> {
            IHttpRequestResponse[] requestResponse = iContextMenuInvocation.getSelectedMessages();
            (new Thread(() -> {
                List<IScanIssue> issues = scanner.doScan(requestResponse[0]);
                /**
                 * add to issues
                 * burp官网不建议使用的方法，通过它添加的漏洞，不会在scanqueue中有记录
                 * 在实际的debug测试中还出现过明明调用成功，却发现连target中都没有记录的情况（可在tabUI中查看扫描情况）
                 */
                for (IScanIssue issue: issues) {
                    burpExtender.callbacks.addScanIssue(issue);
                }
            })).start();
        });
        menuItems.add(sendItem);
        return menuItems;
    }
}

