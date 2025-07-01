package burp;

import burp.*;
import com.google.gson.Gson;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.HttpResponse;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustAllStrategy;
import org.apache.http.ssl.SSLContextBuilder;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.ArrayList;

/**
 * GPTClient 是一个用于与 OpenAI GPT API 进行交互的客户端类。
 * 它提供了分析 HTTP 请求和响应的功能，并将结果返回给调用方。
 */
public class GPTClient {
    private final IBurpExtenderCallbacks callbacks;
    private final Gson gson = new Gson();
    private String apiKey;
    private String apiUrl;
    private String model;
    private static final int CONNECT_TIMEOUT = 30000; // 30秒连接超时
    private static final int SOCKET_TIMEOUT = 60000; // 60秒socket超时
    private static final int MAX_RETRIES = 3; // 最大重试次数

    /**
     * 构造函数，初始化 GPTClient 对象。
     *
     * @param callbacks Burp Suite 提供的回调接口，用于与 Burp Suite 进行交互。
     */
    public GPTClient(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
    }

    private CloseableHttpClient createHttpClient() {
        try {
            // 创建连接管理器
            PoolingHttpClientConnectionManager connectionManager = new PoolingHttpClientConnectionManager();
            connectionManager.setMaxTotal(20);
            connectionManager.setDefaultMaxPerRoute(10);

            // 创建 SSL 上下文
            SSLContextBuilder sslContextBuilder = new SSLContextBuilder();
            sslContextBuilder.loadTrustMaterial(null, new TrustAllStrategy());
            SSLConnectionSocketFactory sslSocketFactory = new SSLConnectionSocketFactory(
                    sslContextBuilder.build(),
                    (hostname, session) -> true);

            // 创建请求配置
            RequestConfig config = RequestConfig.custom()
                    .setConnectTimeout(CONNECT_TIMEOUT)
                    .setSocketTimeout(SOCKET_TIMEOUT)
                    .setConnectionRequestTimeout(CONNECT_TIMEOUT)
                    .build();

            // 构建 HTTP 客户端
            return HttpClientBuilder.create()
                    .setConnectionManager(connectionManager)
                    .setDefaultRequestConfig(config)
                    .setSSLSocketFactory(sslSocketFactory)
                    .setConnectionTimeToLive(30, TimeUnit.SECONDS)
                    .setRetryHandler((exception, executionCount, context) -> {
                        if (executionCount > 3) {
                            return false;
                        }
                        try {
                            Thread.sleep(1000 * executionCount);
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                            return false;
                        }
                        return true;
                    })
                    .build();
        } catch (NoSuchAlgorithmException | KeyStoreException | KeyManagementException e) {
            logError("Failed to create HTTP client", e);
            throw new RuntimeException("创建 HTTP 客户端失败: " + e.getMessage(), e);
        }
    }

    private void logError(String message, Exception e) {
        callbacks.printError("BurpGPT Error: " + message);
        if (e != null) {
            callbacks.printError("Exception: " + e.getMessage());
            // 只打印前5行堆栈跟踪，避免日志过长
            StackTraceElement[] stackTrace = e.getStackTrace();
            for (int i = 0; i < Math.min(5, stackTrace.length); i++) {
                callbacks.printError(stackTrace[i].toString());
            }
        }
    }

    /**
     * 测试 API 连接是否可用
     *
     * @param apiKey API 密钥
     * @param apiUrl API URL
     * @param model 模型名称
     * @param testPrompt 测试提示语
     * @return 测试响应
     */
    //---------------------------------------创建请求测试，测试大模型连接性-----------------------------
    public String testConnection(String apiKey, String apiUrl, String model, String testPrompt) {
        this.apiKey = apiKey;
        this.apiUrl = apiUrl;
        this.model = model;

        try (CloseableHttpClient httpClient = createHttpClient()) {
            HttpPost httpPost = new HttpPost(apiUrl);

            // 构建测试请求
            GPTRequest gptRequest = new GPTRequest(
                    model,
                    testPrompt,
                    100
            );

            // 设置请求头
            httpPost.setHeader("Content-Type", "application/json");
            httpPost.setHeader("Authorization", "Bearer " + apiKey);
            httpPost.setEntity(new StringEntity(gson.toJson(gptRequest)));

            // 记录请求信息
            callbacks.printOutput("Testing API connection...");
            callbacks.printOutput("URL: " + apiUrl);
            callbacks.printOutput("Model: " + model);

            // 执行请求并解析响应
            return httpClient.execute(httpPost, httpResponse -> {
                int statusCode = httpResponse.getStatusLine().getStatusCode();
                String responseBody = readResponseBody(httpResponse);
                callbacks.printOutput("Response status code: " + statusCode);
                callbacks.printOutput("Response body: " + responseBody);

                if (statusCode == 200) {
                    GPTResponse gptResponse = gson.fromJson(responseBody, GPTResponse.class);
                    if (gptResponse.choices != null && !gptResponse.choices.isEmpty()) {
                        String content = gptResponse.choices.get(0).message.content;
                        return String.format("API 连接测试成功！\n" +
                                "模型: %s\n" +
                                "响应内容: %s\n" +
                                "状态码: %d", 
                                model, content, statusCode);
                    }
                    return String.format("API 连接测试成功！\n" +
                            "模型: %s\n" +
                            "状态码: %d", 
                            model, statusCode);
                } else {
                    throw new IOException("API returned status code: " + statusCode + "\nResponse: " + responseBody);
                }
            });
        } catch (IOException e) {
            logError("API connection test failed", e);
            throw new RuntimeException("API 连接测试失败: " + e.getMessage() + 
                "\n请检查:\n1. API Key 是否正确\n2. API URL 是否可以访问\n3. 网络连接是否正常\n4. 是否使用了代理\n5. 防火墙设置是否正确", e);
        }
    }
//---
    private String readResponseBody(HttpResponse response) throws IOException {
        try (InputStream inputStream = response.getEntity().getContent()) {
            ByteArrayOutputStream result = new ByteArrayOutputStream();
            byte[] buffer = new byte[1024];
            int length;
            while ((length = inputStream.read(buffer)) != -1) {
                result.write(buffer, 0, length);
            }
            return result.toString("UTF-8");
        }
    }
//---------------------------------------创建请求测试，测试大模型连接性-----------------------------
    /**
     * 分析 HTTP 请求和响应
     */
    public String analyzeRequestResponse(byte[] request, byte[] response, IHttpService httpService, String customPrompt) {
        if (apiKey == null || apiUrl == null || model == null) {
            return "错误：API 配置未设置。请先测试连接。";
        }

        int retryCount = 0;
        Exception lastException = null;

        while (retryCount < MAX_RETRIES) {
            try (CloseableHttpClient httpClient = createHttpClient()) {
                HttpPost httpPost = new HttpPost(apiUrl);

                // 构建请求体
                String requestBody = buildRequestBody(model, buildCustomPrompt(request, response, httpService, customPrompt), 2048);

                // 设置请求头
                httpPost.setHeader("Content-Type", "application/json");
                httpPost.setHeader("Authorization", "Bearer " + apiKey);
                httpPost.setEntity(new StringEntity(requestBody));

                // 记录请求信息
                callbacks.printOutput("开始分析请求 (尝试 " + (retryCount + 1) + "/" + MAX_RETRIES + ")");

                // 执行请求并解析响应
                return httpClient.execute(httpPost, httpResponse -> {
                    int statusCode = httpResponse.getStatusLine().getStatusCode();
                    if (statusCode != 200) {
                        String errorBody = readResponseBody(httpResponse);
                        throw new IOException("API returned status code: " + statusCode + "\nResponse: " + errorBody);
                    }

                    String responseBody = readResponseBody(httpResponse);
                    String analysis = parseResponse(responseBody, model);
                    
                    if (analysis != null) {
                        return analysis;
                    } else {
                        throw new IOException("API 响应格式错误: " + responseBody);
                    }
                });
            } catch (IOException e) {
                lastException = e;
                logError("Request analysis failed (Attempt " + (retryCount + 1) + ")", e);
                retryCount++;
                if (retryCount < MAX_RETRIES) {
                    try {
                        Thread.sleep(2000 * retryCount);
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        break;
                    }
                }
            }
        }

        throw new RuntimeException("分析请求失败: " + lastException.getMessage() + 
            "\n请检查:\n1. 网络连接是否稳定\n2. API 服务器是否响应缓慢\n3. 请求内容是否过大", lastException);
    }

    /**
     * 构建自定义提示词，用于 GPT 分析
     */
    private String buildCustomPrompt(byte[] request, byte[] response, IHttpService httpService, String customPrompt) {
        IRequestInfo requestInfo = callbacks.getHelpers().analyzeRequest(httpService, request);
        StringBuilder prompt = new StringBuilder();

        // 添加请求信息
        prompt.append("请分析以下 HTTP 请求和响应：\n\n");
        prompt.append("请求 URL: ").append(httpService.getProtocol() + "://" + httpService.getHost() + ":" + httpService.getPort() + requestInfo.getUrl().getPath()).append("\n");
        prompt.append("请求方法: ").append(requestInfo.getMethod()).append("\n");
        prompt.append("请求头:\n");
        for (String header : requestInfo.getHeaders()) {
            prompt.append(header).append("\n");
        }
        prompt.append("\n请求体:\n");
        prompt.append(new String(request, requestInfo.getBodyOffset(), request.length - requestInfo.getBodyOffset()));

        // 添加响应信息
        if (response != null) {
            IResponseInfo responseInfo = callbacks.getHelpers().analyzeResponse(response);
            prompt.append("\n\n响应状态码: ").append(responseInfo.getStatusCode()).append("\n");
            prompt.append("响应头:\n");
            for (String header : responseInfo.getHeaders()) {
                prompt.append(header).append("\n");
            }
            prompt.append("\n响应体:\n");
            prompt.append(new String(response, responseInfo.getBodyOffset(), response.length - responseInfo.getBodyOffset()));
        }

        // 添加自定义分析要求
        prompt.append("\n\n请分析以上请求和响应，重点关注：\n");
        prompt.append(customPrompt);

        return prompt.toString();
    }

    /**
     * 根据模型类型构建请求体
     */
    private String buildRequestBody(String model, String prompt, int maxTokens) {
        // 统一用OpenAI格式，兼容deepseek和qwen
        return gson.toJson(new GPTRequest(model, prompt, maxTokens));
    }

    /**
     * 解析API响应
     */
    private String parseResponse(String responseBody, String model) {
        // 统一用OpenAI格式解析，无论deepseek还是qwen
        GPTResponse gptResponse = gson.fromJson(responseBody, GPTResponse.class);
        if (gptResponse.choices != null && !gptResponse.choices.isEmpty()) {
            return gptResponse.choices.get(0).message.content;
        }
        return null;
    }

    /**
     * 内部类，表示 GPT 请求的结构。
     */
    public static class GPTRequest {
        public final String model; // 模型名称
        public final List<Message> messages; // 消息列表
        public final int max_tokens; // 最大令牌数

        /**
         * 构造函数，初始化 GPTRequest 对象。
         *
         * @param model      模型名称
         * @param messages   多轮对话消息列表
         * @param maxTokens  最大令牌数
         */
        public GPTRequest(String model, List<Message> messages, int maxTokens) {
            this.model = model;
            this.messages = messages;
            this.max_tokens = maxTokens;
        }

        // 兼容原有单prompt构造
        public GPTRequest(String model, String prompt, int maxTokens) {
            this.model = model;
            this.messages = new ArrayList<>();
            this.messages.add(new Message("user", prompt));
            this.max_tokens = maxTokens;
        }
    }

    public static class Message {
        public final String role;
        public final String content;

        public Message(String role, String content) {
            this.role = role;
            this.content = content;
        }
    }

    /**
     * GPT API 响应结构
     */
    private static class GPTResponse {
        List<Choice> choices;

        static class Choice {
            Message message;
        }

        static class Message {
            String content;
        }
    }

    /**
     * 通义千问请求结构
     */
    private static class QwenRequest {
        final String model;
        final Input input;
        final Parameters parameters;

        QwenRequest(String model, String prompt, int maxTokens) {
            this.model = model;
            this.input = new Input(prompt);
            this.parameters = new Parameters(maxTokens);
        }

        static class Input {
            final List<Message> messages;

            Input(String prompt) {
                this.messages = new ArrayList<>();
                this.messages.add(new Message("user", prompt));
            }
        }

        static class Parameters {
            final int max_tokens;

            Parameters(int maxTokens) {
                this.max_tokens = maxTokens;
            }
        }
    }

    /**
     * 通义千问响应结构
     */
    private static class QwenResponse {
        Output output;

        static class Output {
            String text;
        }
    }

    public String getApiKey() {
        return apiKey;
    }

    public String getApiUrl() {
        return apiUrl;
    }

    public String getModel() {
        return model;
    }

    // 新增：支持自定义请求体发送AI并返回回复内容
    public String sendCustomRequest(String apiKey, String apiUrl, String requestBody) {
        try (CloseableHttpClient httpClient = createHttpClient()) {
            HttpPost httpPost = new HttpPost(apiUrl);
            httpPost.setHeader("Content-Type", "application/json");
            httpPost.setHeader("Authorization", "Bearer " + apiKey);
            httpPost.setEntity(new StringEntity(requestBody));
            return httpClient.execute(httpPost, httpResponse -> {
                int statusCode = httpResponse.getStatusLine().getStatusCode();
                String responseBody = readResponseBody(httpResponse);
                if (statusCode == 200) {
                    GPTResponse gptResponse = gson.fromJson(responseBody, GPTResponse.class);
                    if (gptResponse.choices != null && !gptResponse.choices.isEmpty()) {
                        return gptResponse.choices.get(0).message.content;
                    }
                    return "AI无回复";
                } else {
                    throw new IOException("API returned status code: " + statusCode + "\nResponse: " + responseBody);
                }
            });
        } catch (IOException e) {
            logError("Custom AI request failed", e);
            throw new RuntimeException("AI请求失败: " + e.getMessage(), e);
        }
    }
}