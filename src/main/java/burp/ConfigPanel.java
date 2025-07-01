package burp;

import burp.IBurpExtenderCallbacks;
import javax.swing.*;
import javax.swing.tree.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Enumeration;

import java.util.Properties;
//Jpanel是javax.swing里的一个类，用于创建一个面板，可以添加组件，如按钮、标签、文本框等
public class ConfigPanel extends JPanel {
    // 创建API密钥输入框，使用JPasswordField以保护敏感信息，private私有，final无法被继承
    // JPasswordField构造方法，参数为字符串，表示默认显示的文本
    private final JTextField apiKeyField = new JTextField("");//密码输入框
    
    // 创建API URL输入框，设置默认值为DeepSeek API地址
    private final JTextField apiUrlField = new JTextField("https://api.deepseek.com/v1/chat/completions");//明文输入框
    
    // 创建模型选择下拉框，提供两个选项，下拉框是JComboBox
    private final JComboBox<String> modelComboBox = new JComboBox<>(new String[]{
        "deepseek-chat", 
        "deepseek-coder",
        "qwen-turbo",
        "qwen-plus",
        "qwen-max"
    });
    
    // 创建提示语编辑区域，设置初始大小为5行40列
    private final JTextArea promptArea = new JTextArea(5, 40);
    
    // 创建分析结果列表模型，用于存储分析结果
    private final DefaultListModel<AnalysisResult> resultListModel = new DefaultListModel<>();
    
    // 创建结果详情显示区域
    private final JTextArea resultArea = new JTextArea();
    
    // GPT客户端实例，用于与API通信
    private final GPTClient gptClient;
    
    //----------------------------提示语面板--------------------------------
    // 创建预设提示语下拉框，包含多个安全分析选项
    private final JComboBox<String> presetPromptComboBox = new JComboBox<>(new String[]{
        "分析请求中的安全漏洞",    // 通用安全分析
        "检查敏感信息泄露",        // 信息泄露检测
        "分析认证机制",           // 认证机制分析
        "检查输入验证",           // 输入验证检查
        "XSS漏洞检测",           // XSS漏洞检测
        "CSRF漏洞检测"           // CSRF漏洞检测
    });
    
    // 创建保存提示语按钮
    private final JButton savePromptButton = new JButton("保存提示语");
    
    // 创建加载提示语按钮
    private final JButton loadPromptButton = new JButton("加载提示语");
    
    // 测试按钮，用于测试API连接
    private JButton testButton;

    // 添加序号计数器
    private int resultCounter = 0;

    private JPanel upperPanel;  // 添加成员变量以便访问上部分面板
    private JTextArea resultTextArea;  // 添加成员变量用于显示操作结果

    // 添加promptTree作为成员变量
    private JTree promptTree;

    // 添加成员变量
    private JTextArea requestArea;
    private JTextArea responseArea;

    // 添加模型选择监听器
    {
        modelComboBox.addActionListener(e -> {
            String selectedModel = (String) modelComboBox.getSelectedItem();
            if (selectedModel != null) {
                if (selectedModel.startsWith("qwen")) {
                    apiUrlField.setText("https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions");
                } else {
                    apiUrlField.setText("https://api.deepseek.com/v1/chat/completions");
                }
            }
        });
    }

    // 构造函数，接收Burp Suite的回调接口和GPT客户端作为参数
    public ConfigPanel(IBurpExtenderCallbacks callbacks, GPTClient gptClient) {
        // 保存GPT客户端引用到成员变量
        this.gptClient = gptClient;
        
        // 设置面板使用边界布局（BorderLayout）
        setLayout(new BorderLayout());

        // 创建标签页面板，用于组织不同的设置页面
        JTabbedPane tabbedPane = new JTabbedPane();

        // 创建三个主要功能面板
        JPanel apiSettingsPanel = createApiSettingsPanel();        // API设置面板
        JPanel promptSettingsPanel = createPromptSettingsPanel();  // 提示语设置面板
        JPanel resultPanel = createResultPanel();                  // 分析结果面板

        // 添加三个标签页到标签页面板
        tabbedPane.addTab("API 设置", null, apiSettingsPanel, "配置 API 相关设置");
        tabbedPane.addTab("提示语设置", null, promptSettingsPanel, "配置提示语相关设置");
        tabbedPane.addTab("分析结果", null, resultPanel, "查看分析结果");

        // 将标签页面板添加到主面板的中央
        add(tabbedPane, BorderLayout.CENTER);

        // 在创建完所有面板后加载配置
        loadConfig();

        // 为预设提示语下拉框添加选择事件监听器
        presetPromptComboBox.addActionListener(e -> {
            // 获取选中的提示语
            String selectedPrompt = (String) presetPromptComboBox.getSelectedItem();
            // 如果选中了提示语，则更新提示语编辑区域
            if (selectedPrompt != null) {
                promptArea.setText(selectedPrompt);
            }
        });

        // 为保存提示语按钮添加点击事件监听器
        savePromptButton.addActionListener(e -> {
            // 获取当前提示语内容
            String prompt = promptArea.getText();
            // 如果提示语不为空，则保存
            if (!prompt.isEmpty()) {
                // 获取当前选中的节点
                DefaultMutableTreeNode selectedNode = (DefaultMutableTreeNode) promptTree.getLastSelectedPathComponent();
                if (selectedNode != null && selectedNode.isLeaf()) {
                    // 如果是叶子节点，更新其内容
                    selectedNode.setUserObject(prompt);
                    ((DefaultTreeModel) promptTree.getModel()).reload(selectedNode);
                    JOptionPane.showMessageDialog(this, "提示语已更新", "成功", JOptionPane.INFORMATION_MESSAGE);
                } else {
                    // 如果没有选中节点或选中的不是叶子节点，提示用户
                    JOptionPane.showMessageDialog(this, "请先选择一个提示语节点", "提示", JOptionPane.WARNING_MESSAGE);
                }
            } else {
                JOptionPane.showMessageDialog(this, "提示语不能为空", "错误", JOptionPane.ERROR_MESSAGE);
            }
        });

        // 为加载提示语按钮添加点击事件监听器
        loadPromptButton.addActionListener(e -> {
            // TODO: 实现从文件加载提示语的功能
            // 显示加载成功的提示对话框
            JOptionPane.showMessageDialog(this, "提示语已加载", "成功", JOptionPane.INFORMATION_MESSAGE);
        });
        //----------------------------提示语面板--------------------------------
    }

    private void loadConfig() {
        try {
            // 创建配置文件对象
            File configFile = new File("burpgpt.properties");
            // 检查配置文件是否存在
            if (configFile.exists()) {
                // 创建Properties对象用于读取配置
                Properties props = new Properties();
                // 使用try-with-resources语句自动关闭文件流
                try (FileInputStream in = new FileInputStream(configFile)) {
                    // 从文件加载配置信息
                    props.load(in);
                }

                // 将配置信息设置到界面组件中
                apiKeyField.setText(props.getProperty("apiKey", ""));  // 加载API密钥
                apiUrlField.setText(props.getProperty("apiUrl", "https://api.deepseek.com/v1/chat/completions"));  // 加载API URL
                modelComboBox.setSelectedItem(props.getProperty("model", "deepseek-chat"));  // 加载选择的模型
                
                // 加载提示语树的内容
                if (promptTree != null) {
                    DefaultMutableTreeNode root = (DefaultMutableTreeNode) promptTree.getModel().getRoot();
                    Enumeration<?> e = root.depthFirstEnumeration();
                    while (e.hasMoreElements()) {
                        DefaultMutableTreeNode node = (DefaultMutableTreeNode) e.nextElement();
                        if (node.isLeaf()) {
                            String nodeName = node.getUserObject().toString();
                            String savedContent = props.getProperty("prompt." + nodeName);
                            if (savedContent != null) {
                                node.setUserObject(savedContent);
                            }
                        }
                    }
                    // 重新加载树模型以显示更新
                    ((DefaultTreeModel) promptTree.getModel()).reload(root);
                }
            }
        } catch (IOException e) {
            // 如果加载过程中发生异常，显示错误提示
            JOptionPane.showMessageDialog(this,
                "加载配置失败: " + e.getMessage(),
                "错误",
                JOptionPane.ERROR_MESSAGE);
        }
    }

    // 创建API设置面板的方法
    private JPanel createApiSettingsPanel() {//方法返回一个JPanel类型的的对象，void是返回空

        //--------------------------------API Settings面板--------------------------------
        // 创建主面板，使用边界布局
        JPanel panel = new JPanel(new BorderLayout());
        //121行分开写如下
        // 1. 先创建布局管理器
        //BorderLayout borderLayout = new BorderLayout();
        // 2. 创建面板
        //JPanel panel = new JPanel();
        // 3. 设置面板的布局
        //panel.setLayout(borderLayout);
        // 调用panel类方法，设置面板标题为"API Settings"
        panel.setBorder(BorderFactory.createTitledBorder("API Settings"));
        //--------------------------------API Settings面板--------------------------------

        //--------------------------------设置API Settings面板--------------------------------  
        // 创建设置面板，使用网格包布局（更灵活的布局方式）
        JPanel settingsPanel = new JPanel(new GridBagLayout());
        // 创建网格包布局的约束对象，用于控制组件的位置和大小
        GridBagConstraints gbc = new GridBagConstraints();
        // 设置组件之间的间距为5像素
        gbc.insets = new Insets(5, 5, 5, 5);
        // 设置组件水平填充
        gbc.fill = GridBagConstraints.HORIZONTAL;

        // 添加API Key输入框
        gbc.gridx = 0;  // 设置x坐标为0（第一列）
        gbc.gridy = 0;  // 设置y坐标为0（第一行）
        settingsPanel.add(new JLabel("API Key:"), gbc);  // 添加标签
        gbc.gridx = 1;  // 移动到下一列
        gbc.weightx = 1.0;  // 设置水平权重为1.0，使输入框可以水平拉伸
        settingsPanel.add(apiKeyField, gbc);  // 添加输入框

        // API URL
        gbc.gridx = 0;
        gbc.gridy = 1;
        settingsPanel.add(new JLabel("API URL:"), gbc);
        gbc.gridx = 1;
        settingsPanel.add(apiUrlField, gbc);

        // Model Selection
        gbc.gridx = 0;
        gbc.gridy = 2;
        settingsPanel.add(new JLabel("Model:"), gbc);
        gbc.gridx = 1;
        settingsPanel.add(modelComboBox, gbc);
        //--------------------------------设置API Settings面板--------------------------------
        // 添加一个分隔线
        gbc.gridx = 0;
        gbc.gridy = 3;
        gbc.gridwidth = 2;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        settingsPanel.add(new JSeparator(), gbc);   
        //--------------------------------测试按钮和状态面板--------------------------------
        // 创建测试按钮和状态面板
        JPanel testPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 0));
        testButton = new JButton("测试 API 连接");//JButton testButton = new JButton("测试 API 连接");
        //e是事件，testApiConnection()是方法，testApiConnection()方法在190行    
        testButton.addActionListener(e -> testApiConnection());
        
        // 创建状态显示面板
        JPanel statusBox = new JPanel();
        statusBox.setPreferredSize(new Dimension(100, 25));
        statusBox.setBorder(BorderFactory.createLineBorder(Color.GRAY));
        statusBox.setBackground(Color.RED);
        JLabel statusLabel = new JLabel("未连接");
        statusLabel.setForeground(Color.WHITE);
        statusBox.add(statusLabel);
        //俩个按钮加入到testPanel里面
        testPanel.add(testButton);
        testPanel.add(statusBox);
        //--------------------------------测试按钮和状态面板--------------------------------
        // 将测试面板添加到设置面板
        gbc.gridx = 0;
        gbc.gridy = 4;
        gbc.gridwidth = 2;
        gbc.fill = GridBagConstraints.NONE;
        gbc.anchor = GridBagConstraints.CENTER;
        settingsPanel.add(testPanel, gbc);

        // 将设置面板添加到主面板
        panel.add(settingsPanel, BorderLayout.NORTH);

        return panel;
    }

    private void testApiConnection() {
        String apiKey = apiKeyField.getText();
        String apiUrl = apiUrlField.getText();
        String model = (String) modelComboBox.getSelectedItem();

        if (apiKey.isEmpty() || apiUrl.isEmpty()) {
            JOptionPane.showMessageDialog(this, 
                "请填写 API Key 和 API URL", 
                "错误", 
                JOptionPane.ERROR_MESSAGE);
            return;
        }
//--------------------------------deepseek连接测试--------------------------------
        // 创建测试请求prompt
        String testPrompt = "Hello, this is a test message.";
        
        // 在新线程中执行测试
        new Thread(() -> {
            try {
                // rivate final GPTClient gptClient;   上面定义了类GPTClient，gptClient是类GPTClient的实例
                //链接deepseek的方法，response是deepseek的返回值
                String response = gptClient.testConnection(apiKey, apiUrl, model, testPrompt);
                //在UI线程中执行，SwingUtilities.invokeLater()是Swing类库提供的一个方法，用于在UI线程中执行任务
                SwingUtilities.invokeLater(() -> {
                    if (response != null && !response.isEmpty()) {
                        // 保存配置
                        saveConfig();
                        // 更新状态显示
                        JPanel statusBox = (JPanel) ((JPanel) testButton.getParent()).getComponent(1);
                        statusBox.setBackground(Color.GREEN);
                        JLabel statusLabel = (JLabel) statusBox.getComponent(0);
                        statusLabel.setText("已连接");
                        JOptionPane.showMessageDialog(this, 
                            "API 连接测试成功！\n模型: " + model, 
                            "成功", 
                            JOptionPane.INFORMATION_MESSAGE);
                    } else {
                        // 更新状态显示
                        JPanel statusBox = (JPanel) ((JPanel) testButton.getParent()).getComponent(1);
                        statusBox.setBackground(Color.RED);
                        JLabel statusLabel = (JLabel) statusBox.getComponent(0);
                        statusLabel.setText("连接失败");
                        JOptionPane.showMessageDialog(this, 
                            "API 连接测试失败，请检查配置", 
                            "错误", 
                            JOptionPane.ERROR_MESSAGE);
                    }
                });
            } catch (Exception e) {
                SwingUtilities.invokeLater(() -> {
                    // 更新状态显示
                    JPanel statusBox = (JPanel) ((JPanel) testButton.getParent()).getComponent(1);
                    statusBox.setBackground(Color.RED);
                    JLabel statusLabel = (JLabel) statusBox.getComponent(0);
                    statusLabel.setText("连接失败");
                    JOptionPane.showMessageDialog(this, 
                        "API 连接测试失败: " + e.getMessage(), 
                        "错误", 
                        JOptionPane.ERROR_MESSAGE);
                });
            }
        }).start();
    }
//--------------------------------deepseek连接测试--------------------------------

//--------------------------------保存配置到文件--------------------------------
    // 保存配置到文件的方法
    private void saveConfig() {
        try {
            // 创建Properties对象用于存储配置信息
            Properties props = new Properties();
            // 将当前配置保存到Properties对象中
            props.setProperty("apiKey", apiKeyField.getText());  // 保存API密钥
            props.setProperty("apiUrl", apiUrlField.getText());  // 保存API URL
            props.setProperty("model", (String) modelComboBox.getSelectedItem());  // 保存选择的模型
            
            // 保存提示语树的内容
            DefaultMutableTreeNode root = (DefaultMutableTreeNode) promptTree.getModel().getRoot();
            Enumeration<?> e = root.depthFirstEnumeration();
            while (e.hasMoreElements()) {
                DefaultMutableTreeNode node = (DefaultMutableTreeNode) e.nextElement();
                if (node.isLeaf()) {
                    String nodeName = node.getUserObject().toString();
                    props.setProperty("prompt." + nodeName, nodeName);
                }
            }

            // 创建配置文件对象
            File configFile = new File("burpgpt.properties");
            // 使用try-with-resources语句自动关闭文件流
            try (FileOutputStream out = new FileOutputStream(configFile)) {
                // 将配置信息写入文件
                props.store(out, "BurpGPT Configuration");
            }
        } catch (IOException e) {
            // 如果保存过程中发生异常，显示错误提示
            JOptionPane.showMessageDialog(this,
                "保存配置失败: " + e.getMessage(),
                "错误",
                JOptionPane.ERROR_MESSAGE);
        }
    }
//--------------------------------保存配置到文件--------------------------------

//--------------------------------提示语设置面板--------------------------------
    // 创建提示语设置面板的方法
    private JPanel createPromptSettingsPanel() {
        // 创建主面板，使用边界布局
        JPanel panel = new JPanel(new BorderLayout());
        // 设置面板标题为"Prompt Settings"
        panel.setBorder(BorderFactory.createTitledBorder("Prompt Settings"));

        // 创建左侧预设提示语面板，使用网格布局，3行1列，组件间距5像素
        JPanel leftPanel = new JPanel(new GridLayout(3, 1, 5, 5));
        // 设置面板边距为5像素
        leftPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

        // 创建预设提示语树形面板
        JPanel presetPanel = new JPanel(new BorderLayout());
        presetPanel.setBorder(BorderFactory.createTitledBorder("提示语"));
        
        // 创建树形模型
        DefaultMutableTreeNode root = new DefaultMutableTreeNode("提示语");
        // 添加一级节点
        DefaultMutableTreeNode securityNode = new DefaultMutableTreeNode("安全分析");
        securityNode.add(new DefaultMutableTreeNode("基础安全分析"));
        securityNode.add(new DefaultMutableTreeNode("检查敏感信息泄露"));
        securityNode.add(new DefaultMutableTreeNode("分析认证机制"));
        securityNode.add(new DefaultMutableTreeNode("检查输入验证"));
        root.add(securityNode);
        
        DefaultMutableTreeNode xssNode = new DefaultMutableTreeNode("XSS检测");
        xssNode.add(new DefaultMutableTreeNode("基础XSS检测"));
        xssNode.add(new DefaultMutableTreeNode("XSS专家分析"));
        root.add(xssNode);
        
        DefaultMutableTreeNode csrfNode = new DefaultMutableTreeNode("CSRF检测");
        csrfNode.add(new DefaultMutableTreeNode("基础CSRF检测"));
        root.add(csrfNode);

        DefaultMutableTreeNode modelNode = new DefaultMutableTreeNode("专业模版");
        modelNode.add(new DefaultMutableTreeNode("你是一个网络安全专家，专注于XSS漏洞的检测和绕过WAF。我会给你完整的请求包和相应包。你需要通过以下步骤分析请求和响应 :\n1. 判断是否存在XSS漏洞\n● 检查输入点是否被正确处理转义  \n● 观察响应中是否包含未经过滤的注入代码  \n● 查看JavaScript是否能成功执行（例如alertconsole.log出现）  \n● 检查HTML结构是否被破坏或修改\n2. 判断是否被WAF拦截\n● 响应状态码是否为403406429等异常状态  \n● 响应内容中是否包含拦截提示安全警告或错误页面  \n● 检查是否返回空白页面或与预期完全不同的内容  \n● 注入的代码是否被完全删除或明显修改\n3. WAF绕过技术\n● 大小写混淆：如ScRiPt代替script  \n● HTML实体编码：使用<&#x3c;等替代<  \n● 拆分向量：将危险标签分割，如jav+ascript:  \n● 使用别名：使用事件处理或其他标签如imgiframe  \n● 双重编码：对已编码的内容再次编码  \n● 使用无害HTML标签的属性事件  \n● Base64编码URL编码组合\n【重要！】当你建议新的HTTP请求时，请严格按照以下规范提供:\n1. 必须包含完整的HTTP请求行所有必需的HTTP头空行和请求体  \n2. 请求行必须包含HTTP方法请求路径和HTTP版本  \n3. 必须包含Host头部  \n4. 对于POST请求，必须包含正确的Content-Type和Content-Length  \n5. 维持原始请求中的所有其他必要头部  \n6. 在提供HTTP请求之前，使用``http标记，之后使用``结束  \n7. 不要添加任何额外的格式或说明文字到HTTP请求中  \n8. 确保请求体（如有）内容完整且格式正确\n示例格式  \n  \nPOST /example.php HTTP/1.1  \nHost: example.com  \nUser-Agent: Mozilla/5.0  \nContent-Type: application/x-www-form-urlencoded  \nContent-Length: 27  \nConnection: close  \n  \nparam1=value1&param2=value2  \n一、WAF存在性检测阶段\n基础特征分析\n检查HTTP响应头中是否包含CloudflareAkamaiImperva等WAF标识\n分析响应状态码异常（如403406501非预期状态）\n计算请求响应时间差（>2秒可能触发行为分析）\n二、基础注入验证\n无害探针注入\n<svg%0aonload=confirm(1)>\n\">  \n响应特征比对\n原始payload留存率分析（完整度80%？）\n特殊字符存活统计（<>\"'等字符过滤情况）\n上下文语义完整性检测（是否破坏原有HTML结构）  \n三、WAF拦截判定矩阵\n请建立三维判定模型  \n检测维度\t阳性特征\t权重\n响应内容\t包含blockedforbiddendetected等关键词\t0.7\nHTTP状态码\t403406419503\t0.9\n响应延迟\t1500ms\t0.5\n字符转换\t>50%特殊字符被编码删除\t0.8\n综合评分1.5分判定为WAF拦截  \n四、绕过策略决策树\n请按优先级尝试以下向量  \n1. 字符级绕过\n● Unicode编码：\\u003cscript\\u003e  \n● HTML实体变异：<script>  <script&GT;  \n● 控制字符注入：%0d%0a%09等\n2. 语法级绕过\n● 标签属性嵌套：  \n● 事件处理变形：onpointerenter=alert(1)  \n● SVG矢量封装：<svg/onload=alert(1)>\n3. 协议级混淆\n● data协议注入：  \n● JS伪协议分割：java&#x09;script:alert(1)\n4. 逻辑级混淆\n● 字符串拆解：eval('al'+'er'+'t(1)')  \n● 环境检测触发：window.innerWidth>0&&alert(1)\n5. 高级iframe技术\n● 叠加iframe：  \n● 隐形iframe：\n五、XSS成功验证标准\n需满足以下任二项即为成功  \nDOM变更检测\ndocument.documentElement.innerHTML包含有效payload\n新建script节点可见于DOM树  \n错误诱导\n生成非常规JS错误（如未定义函数故意调用）  \n注意！！！！！！不需要过多回复，只需要给我结论，是否xss成功，是否被waf拦截，然后按照上述格式要求给出一个完整的修改后的HTTP请求，请确保请求格式完全正确，我会使用你提供的请求进行测试，并将结果返回给你继续分析，如果没有收到相应包，那就直接判断被拦截，xss失败"));
        root.add(modelNode);
        
        // 创建树形控件
        promptTree = new JTree(root);
        promptTree.setRootVisible(false);  // 隐藏根节点
        promptTree.setShowsRootHandles(true);
        
        // 添加树形控件的选择监听器
        promptTree.addTreeSelectionListener(e -> {
            DefaultMutableTreeNode node = (DefaultMutableTreeNode) promptTree.getLastSelectedPathComponent();
            if (node != null && node.isLeaf()) {
                // 如果是叶子节点，更新提示语编辑区域
                promptArea.setText(node.getUserObject().toString());
            }
        });
        
        // 添加提示语编辑区域的监听器，burp右键会跟着提示语更新
        promptArea.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            public void changedUpdate(javax.swing.event.DocumentEvent e) {
                updateSelectedNode();
            }
            public void removeUpdate(javax.swing.event.DocumentEvent e) {
                updateSelectedNode();
            }
            public void insertUpdate(javax.swing.event.DocumentEvent e) {
                updateSelectedNode();
            }
            
            private void updateSelectedNode() {
                DefaultMutableTreeNode selectedNode = (DefaultMutableTreeNode) promptTree.getLastSelectedPathComponent();
                if (selectedNode != null && selectedNode.isLeaf()) {
                    // 更新节点的用户对象为提示语内容
                    selectedNode.setUserObject(promptArea.getText());
                    // 重新加载树模型以显示更新
                    ((DefaultTreeModel) promptTree.getModel()).reload(selectedNode);
                    // 保存配置
                    saveConfig();
                }
            }
        });
        
        // 创建树形控件的滚动面板
        JScrollPane treeScrollPane = new JScrollPane(promptTree);
        presetPanel.add(treeScrollPane, BorderLayout.CENTER);
        
        // 创建按钮面板
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        
        // 添加新增按钮
        JButton addButton = new JButton("新增");
        addButton.addActionListener(e -> {
            DefaultMutableTreeNode selectedNode = (DefaultMutableTreeNode) promptTree.getLastSelectedPathComponent();
            if (selectedNode == null) {
                selectedNode = root;
            }
            
            String name = JOptionPane.showInputDialog(this, "请输入名称：");
            if (name != null && !name.trim().isEmpty()) {
                DefaultMutableTreeNode newNode = new DefaultMutableTreeNode(name);
                selectedNode.add(newNode);
                ((DefaultTreeModel) promptTree.getModel()).reload(selectedNode);
                promptTree.expandPath(new TreePath(selectedNode.getPath()));
            }
        });
        
        // 添加删除按钮
        JButton deleteButton = new JButton("删除");
        deleteButton.addActionListener(e -> {
            DefaultMutableTreeNode selectedNode = (DefaultMutableTreeNode) promptTree.getLastSelectedPathComponent();
            if (selectedNode != null && selectedNode != root) {
                DefaultMutableTreeNode parent = (DefaultMutableTreeNode) selectedNode.getParent();
                parent.remove(selectedNode);
                ((DefaultTreeModel) promptTree.getModel()).reload(parent);
            }
        });
        
        buttonPanel.add(addButton);
        buttonPanel.add(deleteButton);
        presetPanel.add(buttonPanel, BorderLayout.SOUTH);

        // 创建提示语编辑区域的滚动面板
        JScrollPane promptScrollPane = new JScrollPane(promptArea);

        // 创建按钮面板，使用流式布局，按钮靠左对齐
        JPanel editButtonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        editButtonPanel.add(savePromptButton);  // 添加保存按钮
        editButtonPanel.add(loadPromptButton);  // 添加加载按钮

        // 创建水平分割面板，左侧是预设提示语面板，右侧是提示语编辑区域
        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, presetPanel, promptScrollPane);
        splitPane.setDividerLocation(200);  // 设置分割条的位置为200像素

        // 将分割面板添加到主面板的中央
        panel.add(splitPane, BorderLayout.CENTER);
        // 将按钮面板添加到主面板的底部
        panel.add(editButtonPanel, BorderLayout.SOUTH);

        // 返回创建好的提示语设置面板
        return panel;
    }
//--------------------------------提示语设置面板--------------------------------

//--------------------------------分析结果面板----------------------------------
    // 创建分析结果面板的方法
    private JPanel createResultPanel() {
        // 创建主面板，使用边界布局
        JPanel panel = new JPanel(new BorderLayout());
        // 设置面板标题为"Analysis Results"
        panel.setBorder(BorderFactory.createTitledBorder("Analysis Results"));

        // 创建顶部按钮面板，使用流式布局，按钮靠右对齐
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        // 创建清空结果按钮
        JButton clearButton = new JButton("清空结果");
        // 为清空按钮添加点击事件监听器
        clearButton.addActionListener(e -> {
            // 清空结果列表
            clearResults();
        });
        // 将清空按钮添加到按钮面板
        buttonPanel.add(clearButton);

        // 创建结果列表，使用DefaultListModel存储结果
        JList<AnalysisResult> resultList = new JList<>(resultListModel);
        // 设置列表的选择模式为单选
        resultList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        // 添加列表选择监听器
        resultList.addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                AnalysisResult selectedResult = resultList.getSelectedValue();
                if (selectedResult != null) {
                    // 更新结果详情显示
                    resultArea.setText(selectedResult.getAnalysis());
                    // 更新请求和响应显示
                    updateRequestResponseDisplay(selectedResult);
                }
            }
        });

        // 创建左侧垂直分割面板
        JSplitPane leftSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
                new JScrollPane(resultList),  // 上部分：结果列表
                createRequestResponsePanel()); // 下部分：请求响应面板
        leftSplitPane.setDividerLocation(200);  // 设置分割条的位置为200像素

        // 创建水平分割面板，左侧是结果列表和请求响应面板，右侧是结果详情
        JSplitPane mainSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                leftSplitPane,  // 左侧面板
                createDetailPanel()); // 右侧面板
        mainSplitPane.setDividerLocation(400);  // 设置分割条的位置为400像素

        // 将按钮面板添加到主面板顶部
        panel.add(buttonPanel, BorderLayout.NORTH);
        // 将主分割面板添加到主面板中央
        panel.add(mainSplitPane, BorderLayout.CENTER);
        // 返回创建好的分析结果面板
        return panel;
    }

    // 创建请求响应面板
    private JPanel createRequestResponsePanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createTitledBorder("请求/响应详情"));

        // 创建请求和响应文本区域
        JTextArea requestArea = new JTextArea();
        JTextArea responseArea = new JTextArea();
        
        // 设置文本区域属性
        for (JTextArea area : new JTextArea[]{requestArea, responseArea}) {
            area.setEditable(false);
            area.setLineWrap(true);
            area.setWrapStyleWord(true);
            area.setFont(new Font("Monospaced", Font.PLAIN, 12));
        }

        // 创建水平分割面板
        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                new JScrollPane(requestArea),  // 左侧：请求
                new JScrollPane(responseArea)); // 右侧：响应
        splitPane.setDividerLocation(400);  // 设置分割条的位置为400像素

        // 保存文本区域的引用
        this.requestArea = requestArea;
        this.responseArea = responseArea;

        panel.add(splitPane, BorderLayout.CENTER);
        return panel;
    }

    // 更新请求和响应显示
    private void updateRequestResponseDisplay(AnalysisResult result) {
        if (result != null) {
            // 获取请求和响应数据
            byte[] request = result.getRequest();
            byte[] response = result.getResponse();
            
            // 更新显示
            if (request != null) {
                requestArea.setText(new String(request));
            } else {
                requestArea.setText("无请求数据");
            }
            
            if (response != null) {
                responseArea.setText(new String(response));
            } else {
                responseArea.setText("无响应数据");
            }
        }
    }

    // 修改添加分析结果的方法
    public void addAnalysisResult(AnalysisResult result) {
        if (result == null) {
            return;
        }
        SwingUtilities.invokeLater(() -> {
            resultCounter++;
            AnalysisResult newResult = new AnalysisResult(
                resultCounter,
                result.getTimestamp(),
                result.getUrl(),
                result.getAnalysis(),
                result.getRequest(),
                result.getResponse()
            );
            // 将新结果添加到列表的开头
            resultListModel.insertElementAt(newResult, 0);
            // 自动选择新添加的结果
            JList<AnalysisResult> resultList = (JList<AnalysisResult>) ((JScrollPane) ((JSplitPane) ((JSplitPane) ((JPanel) getComponent(0)).getComponent(0)).getLeftComponent()).getTopComponent()).getViewport().getView();
            resultList.setSelectedIndex(0);
            // 显示分析结果
            resultArea.setText(newResult.getAnalysis());
            // 显示请求和响应
            updateRequestResponseDisplay(newResult);
        });
    }

    // 修改清空结果的方法
    private void clearResults() {
        resultListModel.clear();
        resultArea.setText("");
        requestArea.setText("");
        responseArea.setText("");
        resultCounter = 0;  // 重置计数器
    }

    // 创建结果详情面板
    private JPanel createDetailPanel() {
        JPanel detailPanel = new JPanel(new BorderLayout());
        
        // 创建水平分割面板，左侧是结果详情，右侧是操作按钮
        JSplitPane detailSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                createResultDetailPanel(),  // 结果详情面板
                createActionPanel());  // 操作按钮面板
        detailSplitPane.setDividerLocation(400);  // 设置分割条的位置为400像素
        
        detailPanel.add(detailSplitPane, BorderLayout.CENTER);
        return detailPanel;
    }

    // 创建结果详情面板
    private JPanel createResultDetailPanel() {
        JPanel resultDetailPanel = new JPanel(new BorderLayout());
        resultDetailPanel.setBorder(BorderFactory.createTitledBorder("分析结果"));

        // 上方：分析结果显示区
        resultArea.setEditable(false);
        resultArea.setLineWrap(true);
        resultArea.setWrapStyleWord(true);
        resultArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        JScrollPane resultScrollPane = new JScrollPane(resultArea);

        // 下方：继续追问区
        JPanel followupPanel = new JPanel(new BorderLayout());
        followupPanel.setBorder(BorderFactory.createTitledBorder("继续追问"));
        JTextArea followupArea = new JTextArea(3, 40);
        followupArea.setLineWrap(true);
        followupArea.setWrapStyleWord(true);
        JScrollPane followupScrollPane = new JScrollPane(followupArea);
        JButton followupButton = new JButton("继续追问");
        followupButton.addActionListener(e -> {
            String lastResult = resultArea.getText();
            String followup = followupArea.getText();
            if (lastResult.trim().isEmpty()) {
                JOptionPane.showMessageDialog(this, "请先选择分析结果", "提示", JOptionPane.WARNING_MESSAGE);
                return;
            }
            if (followup.trim().isEmpty()) {
                JOptionPane.showMessageDialog(this, "追问内容不能为空", "提示", JOptionPane.WARNING_MESSAGE);
                return;
            }
            followupButton.setEnabled(false);
            followupButton.setText("AI处理中...");
            // 构造多轮对话
            java.util.List<burp.GPTClient.Message> messages = new java.util.ArrayList<>();
            messages.add(new burp.GPTClient.Message("user", lastResult));
            messages.add(new burp.GPTClient.Message("user", followup));
            // 发送给AI
            new Thread(() -> {
                try {
                    String apiKey = getApiKey();
                    String apiUrl = getApiUrl();
                    String model = getSelectedModel();
                    String requestBody = new com.google.gson.Gson().toJson(new burp.GPTClient.GPTRequest(model, messages, 1024));
                    String aiReply = gptClient.sendCustomRequest(apiKey, apiUrl, requestBody);
                    javax.swing.SwingUtilities.invokeLater(() -> {
                        resultArea.append("\n\n[追问回复]:\n" + aiReply);
                        followupArea.setText("");
                        followupButton.setEnabled(true);
                        followupButton.setText("继续追问");
                    });
                } catch (Exception ex) {
                    javax.swing.SwingUtilities.invokeLater(() -> {
                        JOptionPane.showMessageDialog(this, "AI请求失败: " + ex.getMessage(), "错误", JOptionPane.ERROR_MESSAGE);
                        followupButton.setEnabled(true);
                        followupButton.setText("继续追问");
                    });
                }
            }).start();
        });
        JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        btnPanel.add(followupButton);
        followupPanel.add(followupScrollPane, BorderLayout.CENTER);
        followupPanel.add(btnPanel, BorderLayout.SOUTH);

        // 垂直分割，上面五分之四，下面五分之一
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, resultScrollPane, followupPanel);
        splitPane.setResizeWeight(0.8); // 上面占80%
        splitPane.setDividerLocation(0.8);
        resultDetailPanel.add(splitPane, BorderLayout.CENTER);
        return resultDetailPanel;
    }

    // 创建操作按钮面板
    private JPanel createActionPanel() {
        JPanel actionPanel = new JPanel(new BorderLayout());
        
        // 创建上下分割面板
        JSplitPane actionSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
                createUpperPanel(),  // 上部分面板
                createLowerPanel()); // 下部分面板
        actionSplitPane.setDividerLocation(200);  // 设置分割条的位置为200像素
        
        actionPanel.add(actionSplitPane, BorderLayout.CENTER);
        return actionPanel;
    }

    // 创建上部分面板
    private JPanel createUpperPanel() {
        upperPanel = new JPanel(new BorderLayout());
        upperPanel.setBorder(BorderFactory.createTitledBorder("操作结果"));
        
        // 创建文本区域用于显示操作结果
        resultTextArea = new JTextArea();
        resultTextArea.setEditable(false);
        resultTextArea.setLineWrap(true);
        resultTextArea.setWrapStyleWord(true);
        
        // 添加滚动面板
        JScrollPane scrollPane = new JScrollPane(resultTextArea);
        upperPanel.add(scrollPane, BorderLayout.CENTER);
        
        return upperPanel;
    }

    // 创建下部分面板
    private JPanel createLowerPanel() {
        JPanel lowerPanel = new JPanel();
        lowerPanel.setLayout(new BoxLayout(lowerPanel, BoxLayout.Y_AXIS));
        lowerPanel.setBorder(BorderFactory.createTitledBorder("操作选项"));
        
        // 添加一键CSRF按钮，实现csrf的功能
        JButton csrfButton = new JButton("一键CSRF");
        csrfButton.setAlignmentX(Component.CENTER_ALIGNMENT);
        csrfButton.addActionListener(e -> {
            String analysisContent = resultArea.getText();
            if (analysisContent == null || analysisContent.trim().isEmpty()) {
                JOptionPane.showMessageDialog(this, "请先选择分析结果", "提示", JOptionPane.WARNING_MESSAGE);
                return;
            }
            
            // 使用正则表达式匹配HTML内容
            String htmlPattern = "<html[^>]*>.*?</html>";
            java.util.regex.Pattern pattern = java.util.regex.Pattern.compile(htmlPattern, 
                java.util.regex.Pattern.DOTALL | java.util.regex.Pattern.CASE_INSENSITIVE);
            java.util.regex.Matcher matcher = pattern.matcher(analysisContent);
            
            if (matcher.find()) {
                String htmlContent = matcher.group();
                // 在操作结果面板中显示匹配到的内容
                resultTextArea.setText(htmlContent);
            } else {
                resultTextArea.setText("未找到HTML内容");
            }
        });
        
        lowerPanel.add(Box.createVerticalStrut(10));  // 添加垂直间距
        lowerPanel.add(csrfButton);
        lowerPanel.add(Box.createVerticalGlue());  // 添加弹性空间
        
        return lowerPanel;
    }

//--------------------------------获取API密钥的方法--------------------------------
    // 获取API密钥的方法
    public String getApiKey() {
        return apiKeyField.getText();
    }
//--------------------------------获取API密钥的方法--------------------------------

//--------------------------------获取API URL的方法--------------------------------
    // 获取API URL的方法
    public String getApiUrl() {
        return apiUrlField.getText();
    }
//--------------------------------获取API URL的方法--------------------------------

//--------------------------------获取当前选择的模型的方法--------------------------------
    // 获取当前选择的模型的方法
    public String getSelectedModel() {
        return (String) modelComboBox.getSelectedItem();
    }
//--------------------------------获取当前选择的模型的方法--------------------------------

//--------------------------------获取当前提示语的方法--------------------------------
    // 获取当前提示语的方法
    public String getPrompt() {
        return promptArea.getText();
    }
//--------------------------------获取当前提示语的方法--------------------------------

    // 修改获取预设提示语列表的方法
    public String[] getPresetPrompts() {
        List<String> prompts = new ArrayList<>();
        DefaultMutableTreeNode root = (DefaultMutableTreeNode) ((JTree) ((JScrollPane) ((JSplitPane) ((JPanel) getComponent(0)).getComponent(0)).getLeftComponent()).getViewport().getView()).getModel().getRoot();
        Enumeration<?> e = root.depthFirstEnumeration();
        while (e.hasMoreElements()) {
            DefaultMutableTreeNode node = (DefaultMutableTreeNode) e.nextElement();
            if (node.isLeaf() && node != root) {
                prompts.add(node.getUserObject().toString());
            }
        }
        return prompts.toArray(new String[0]);
    }

    // 修改获取预设提示语内容的方法
    public String getPresetPromptContent(String promptName) {
        // 从树形控件中查找对应的节点
        JTree promptTree = (JTree) ((JScrollPane) ((JSplitPane) ((JPanel) getComponent(0)).getComponent(0)).getLeftComponent()).getViewport().getView();
        DefaultMutableTreeNode root = (DefaultMutableTreeNode) promptTree.getModel().getRoot();
        Enumeration<?> e = root.depthFirstEnumeration();
        while (e.hasMoreElements()) {
            DefaultMutableTreeNode node = (DefaultMutableTreeNode) e.nextElement();
            if (node.isLeaf() && node.getUserObject().toString().equals(promptName)) {
                return promptArea.getText();
            }
        }
        return promptName;
    }

    // 添加获取树形控件的方法
    public JTree getPromptTree() {
        return promptTree;
    }
}   