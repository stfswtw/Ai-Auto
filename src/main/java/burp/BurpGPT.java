package burp;

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IRequestInfo;
import burp.IScanIssue;
import burp.IScannerCheck;
import burp.IScannerInsertionPoint;
import burp.ITab;

import javax.swing.*;
import javax.swing.tree.DefaultMutableTreeNode;
import java.awt.*;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.Enumeration;

/**
 * BurpGPT 是一个 Burp Suite 扩展插件，用于集成 GPT 分析功能。
 * 它实现了 IBurpExtender、IContextMenuFactory、IScannerCheck 和 ITab 接口，
 * 提供了右键菜单、被动扫描、主动扫描和配置面板的功能。
 */
public class BurpGPT implements IBurpExtender, IContextMenuFactory, IScannerCheck, ITab {
    /**
     * 全局回调接口，用于与 Burp Suite 进行交互。
     */
    private IBurpExtenderCallbacks callbacks;

    /**
     * 标准输出流，用于打印日志信息。
     */
    private PrintWriter stdout;

    /**
     * 配置面板，用于显示和管理 GPT 分析结果。
     */
    private ConfigPanel configPanel;

    /**
     * GPT 客户端，用于调用 GPT 分析服务。
     */
    private GPTClient gptClient;

    /**
     * 注册扩展插件的回调函数。
     * 初始化插件的基本组件，包括回调接口、输出流、GPT 客户端和配置面板。
     *
     * @param callbacks Burp Suite 提供的回调接口
     */
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        // 保存回调接口
        this.callbacks = callbacks;
        
        // 设置标准输出
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        
        // 设置扩展名称
        callbacks.setExtensionName("Auto-Ai");
        
        // 初始化 GPT 客户端
        this.gptClient = new GPTClient(callbacks);
        
        // 注册上下文菜单工厂
        callbacks.registerContextMenuFactory(this);
        
        // 注册扫描检查
        callbacks.registerScannerCheck(this);
        
        // 打印调试信息
        stdout.println("Auto-Ai 插件已加载");
        
        // 异步初始化配置面板
        SwingUtilities.invokeLater(() -> {
            try {
                configPanel = new ConfigPanel(callbacks, gptClient);
                callbacks.addSuiteTab(BurpGPT.this);
                stdout.println("配置面板已初始化");
            } catch (Exception e) {
                stdout.println("初始化配置面板时出错: " + e.getMessage());
                e.printStackTrace(stdout);
            }
        });
    }

    /**
     * 创建右键菜单项
     */
    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        try {
            stdout.println("开始创建菜单项...");
            List<JMenuItem> menuItems = new ArrayList<>();
            
            // 创建主菜单
            JMenu mainMenu = new JMenu("Auto-Ai");
            stdout.println("创建主菜单: Auto-Ai");
            
            // 创建Send to Analyse菜单项
            JMenuItem sendToGPT = new JMenuItem("Send to Analyse");
            
            // 为Send to GPT菜单项添加事件监听器
            sendToGPT.addActionListener(e -> {
                String prompt = configPanel != null ? configPanel.getPrompt() : "请分析以下请求中的安全漏洞";
                sendToGPT(invocation, prompt);
            });
            
            // 将Send to Analyse菜单项添加到主菜单
            mainMenu.add(sendToGPT);
            
            // 将主菜单添加到菜单列表
            menuItems.add(mainMenu);
            
            return menuItems;
        } catch (Exception e) {
            stdout.println("创建菜单时出错: " + e.getMessage());
            e.printStackTrace(stdout);
            return new ArrayList<>();
        }
    }

    /**
     * 根据节点名称获取对应的提示语
     */
    private String getPromptForNode(String nodeName) {
        if (configPanel == null) {
            return null;
        }
        
        // 获取树形结构中的所有节点
        DefaultMutableTreeNode root = (DefaultMutableTreeNode) configPanel.getPromptTree().getModel().getRoot();
        Enumeration<?> e = root.depthFirstEnumeration();
        
        // 遍历所有节点，查找匹配的节点
        while (e.hasMoreElements()) {
            DefaultMutableTreeNode node = (DefaultMutableTreeNode) e.nextElement();
            if (node.getUserObject().toString().equals(nodeName)) {
                // 获取节点的实际内容
                String content = node.getUserObject().toString();
                // 如果节点内容为空，返回默认提示语
                if (content == null || content.isEmpty()) {
                    switch (nodeName) {
                        case "基础安全分析":
                            return "请分析以下请求中的安全漏洞";
                        case "检查敏感信息泄露":
                            return "请检查以下请求中是否存在敏感信息泄露";
                        case "分析认证机制":
                            return "请分析以下请求中的认证机制";
                        case "检查输入验证":
                            return "请检查以下请求中的输入验证";
                        case "基础XSS检测":
                            return "请检测以下请求中是否存在XSS漏洞";
                        case "基础CSRF检测":
                            return "请检测以下请求中是否存在CSRF漏洞";
                        default:
                            return null;
                    }
                }
                return content;
            }
        }
        
        return null;
    }

    /**
     * 将选中的 HTTP 请求和响应发送到 GPT 进行分析，并将结果添加到配置面板中。
     *
     * @param invocation 右键菜单调用上下文
     */
    private void sendToGPT(IContextMenuInvocation invocation, String prompt) {
        IHttpRequestResponse[] messages = invocation.getSelectedMessages();
        if (messages == null || messages.length == 0) {
            callbacks.printError("没有选择任何请求");
            return;
        }

        if (messages.length > 1) {
            callbacks.printError("请只选择一个请求进行分析");
            return;
        }

        IHttpRequestResponse message = messages[0];
        if (message.getRequest() == null) {
            callbacks.printError("选中的请求为空");
            return;
        }

        // 检查 API 配置
        if (gptClient.getApiKey() == null || gptClient.getApiKey().isEmpty()) {
            callbacks.printError("请先配置 API Key");
            return;
        }

        if (gptClient.getApiUrl() == null || gptClient.getApiUrl().isEmpty()) {
            callbacks.printError("请先配置 API URL");
            return;
        }

        if (gptClient.getModel() == null || gptClient.getModel().isEmpty()) {
            callbacks.printError("请先选择模型");
            return;
        }

        // 记录请求信息
        IRequestInfo requestInfo = callbacks.getHelpers().analyzeRequest(message);
        callbacks.printOutput("开始分析请求: " + requestInfo.getUrl());

        // 在新线程中执行分析
        new Thread(() -> {
            try {
                String analysis = gptClient.analyzeRequestResponse(
                        message.getRequest(),
                        message.getResponse(),
                        message.getHttpService(),
                        prompt  // 使用传入的提示语
                );

                if (analysis != null && !analysis.isEmpty()) {
                    SwingUtilities.invokeLater(() -> {
                        configPanel.addAnalysisResult(new AnalysisResult(
                                0,  // 临时ID，ConfigPanel会重新分配
                                System.currentTimeMillis(),
                                requestInfo.getUrl().toString(),
                                analysis,
                                message.getRequest(),  // 添加请求数据
                                message.getResponse()  // 添加响应数据
                        ));
                        callbacks.printOutput("分析完成: " + requestInfo.getUrl());
                    });
                } else {
                    callbacks.printError("分析结果为空");
                }
            } catch (Exception e) {
                callbacks.printError("分析请求失败: " + e.getMessage());
                e.printStackTrace();
            }
        }).start();
    }

    /**
     * 获取配置面板的标签名称。
     *
     * @return 配置面板的标签名称
     */
    @Override
    public String getTabCaption() {
        return "Ai-Auto";
    }

    /**
     * 获取配置面板的 UI 组件。
     *
     * @return 配置面板的 UI 组件
     */
    @Override
    public Component getUiComponent() {
        return configPanel;
    }

    /**
     * 实现被动扫描逻辑。
     *
     * @param requestResponse HTTP 请求和响应对象
     * @return 扫描发现问题的列表
     */
    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse requestResponse) {
        List<IScanIssue> issues = new ArrayList<>();
        // 在这里实现被动扫描的逻辑
        // 例如：分析请求和响应数据，生成扫描问题
        return issues;
    }

    /**
     * 实现主动扫描逻辑。
     *
     * @param baseRequestResponse 基础 HTTP 请求和响应对象
     * @param insertionPoint 插入点对象
     * @return 扫描发现问题的列表
     */
    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        List<IScanIssue> issues = new ArrayList<>();
        // 在这里实现主动扫描的逻辑
        return issues;
    }

    /**
     * 合并重复的扫描问题。
     *
     * @param existingIssue 已存在的扫描问题
     * @param newIssue 新发现的扫描问题
     * @return 合并结果的标准值
     */
    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        // 返回合并结果的标准值
        return -1; // 0 表示相同，正数表示 existingIssue 更优先，负数表示 newIssue 更优先
    }
}