package burp;

/**
 * AnalysisResult 是一个用于存储分析结果的类。
 * 它包含时间戳、URL、分析内容、请求数据和响应数据等字段，用于记录每次分析的结果。
 */
public class AnalysisResult {
    /**
     * 时间戳，表示分析结果的生成时间。
     */
    private final long timestamp;

    /**
     * URL，表示分析的目标请求的 URL。
     */
    private final String url;

    /**
     * 分析内容，表示 GPT 对请求和响应的分析结果。
     */
    private final String analysis;

    /**
     * 请求数据
     */
    private final byte[] request;

    /**
     * 响应数据
     */
    private final byte[] response;

    private final int id;

    /**
     * 构造函数，用于初始化 AnalysisResult 对象。
     *
     * @param id        序号
     * @param timestamp 时间戳，表示分析结果的生成时间
     * @param url       URL，表示分析的目标请求的 URL
     * @param analysis  分析内容，表示 GPT 对请求和响应的分析结果
     * @param request   请求数据
     * @param response  响应数据
     */
    public AnalysisResult(int id, long timestamp, String url, String analysis, byte[] request, byte[] response) {
        this.id = id;
        this.timestamp = timestamp;
        this.url = url;
        this.analysis = analysis;
        this.request = request;
        this.response = response;
    }

    /**
     * 返回分析结果的字符串表示形式。
     * 格式为："[序号] [时间戳] URL"。
     *
     * @return 分析结果的字符串表示形式
     */
    @Override
    public String toString() {
        return String.format("[%d] [%tT] %s", id, timestamp, url);
    }

    /**
     * 获取分析内容。
     *
     * @return 分析内容
     */
    public String getAnalysis() {
        return analysis;
    }

    public long getTimestamp() {
        return timestamp;
    }

    public String getUrl() {
        return url;
    }

    /**
     * 获取请求数据
     *
     * @return 请求数据
     */
    public byte[] getRequest() {
        return request;
    }

    /**
     * 获取响应数据
     *
     * @return 响应数据
     */
    public byte[] getResponse() {
        return response;
    }
}