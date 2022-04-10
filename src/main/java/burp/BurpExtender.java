package burp;

import burp.scan.Scanner;
import burp.ui.Tags;

import java.io.PrintWriter;

/**
 * @author ：metaStor
 * @date ：Created 2022/4/6 4:12 PM
 * @description： 入口
 * */
public class BurpExtender implements IBurpExtender
{
    private final String NAME = "SpringScan";
    private final String VERSION = "1.1";

    public IBurpExtenderCallbacks callbacks;
    public IExtensionHelpers helpers;
    public PrintWriter stdout;
    public PrintWriter stderr;
    public Tags tags;

    //
    // implement IBurpExtender
    //

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
        // keep a reference to our callbacks object
        this.callbacks = callbacks;

        // set our extension name
        this.callbacks.setExtensionName(NAME);

        // set helpers
        this.helpers = this.callbacks.getHelpers();

        // obtain our output and error streams
        this.stdout = new PrintWriter(this.callbacks.getStdout(), true);
        this.stderr = new PrintWriter(this.callbacks.getStderr(), true);

        // 添加tag标签到ui
        tags = new Tags(callbacks, this.NAME);

        // 注册Scanner
        this.callbacks.registerScannerCheck(new Scanner(this));

        // 输出插件信息
        this.stdout.println(this.extenderInfo());
    }

    public String extenderInfo() {
        String logo = " ____             _             ____                  \n/ ___| _ __  _ __(_)_ __   __ _/ ___|  ___ __ _ _ __  \n\\___ \\| '_ \\| '__| | '_ \\ / _` \\___ \\ / __/ _` | '_ \\ \n ___) | |_) | |  | | | | | (_| |___) | (_| (_| | | | |\n|____/| .__/|_|  |_|_| |_|\\__, |____/ \\___\\__,_|_| |_|\n      |_|                 |___/                       \n";
        String author = "by metaStor";
        String line = "\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t";
        String payloads = "Support Payload:\n[+] Spring Core RCE (CVE-2022-22965)\n[+] Spring Cloud Function SpEL RCE (CVE-2022-22963)\n";
        return logo + line + "V" + this.VERSION + line + author + "\n" + payloads;
    }
}