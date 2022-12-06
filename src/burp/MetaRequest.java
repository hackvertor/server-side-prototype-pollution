package burp;

class MetaRequest {
    private IHttpRequestResponse request;
    private long timestamp;

    MetaRequest(IHttpRequestResponse req) {
        request = req;
        timestamp = System.currentTimeMillis();
    }

    public IHttpRequestResponse getRequest() {
        return request;
    }

    public long getTimestamp() {
        return timestamp;
    }
}