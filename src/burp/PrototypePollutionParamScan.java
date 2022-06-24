package burp;

import com.google.gson.JsonElement;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class PrototypePollutionParamScan extends ParamScan {
    private final String DETAIL = "This application is vulnerable to Server side prototype pollution";
    private final String CANARY = "f1e3f7a9";
    private final Integer MAX_RETRIES = 3;

    public PrototypePollutionParamScan(String name) {
        super(name);
    }

    @Override
    List<IScanIssue> doScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        Utilities.out("Insertion point:" + insertionPoint.getInsertionPointType());
        switch(insertionPoint.getInsertionPointType()) {
            case IScannerInsertionPoint.INS_PARAM_BODY:
            case IScannerInsertionPoint.INS_PARAM_URL:
            case IScannerInsertionPoint.INS_PARAM_COOKIE:
            case IScannerInsertionPoint.INS_PARAM_JSON:
                Utilities.out("Found insertion point:" + insertionPoint.getInsertionPointType());
                injectInsertionPoint(baseRequestResponse, insertionPoint);
                break;
        }
        return null;
    }

    private void injectInsertionPoint(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        IHttpService service = baseRequestResponse.getHttpService();
        for (Map.Entry<String, String[]> technique : PrototypePollutionBodyScan.jsonTechniques.entrySet()) {
            String attackType = technique.getKey();
            String nullifyInjection = technique.getValue()[2];
            String baseValue = insertionPoint.getBaseValue();
            byte[] attackReq;

            if (insertionPoint.getInsertionPointType() != IScannerInsertionPoint.INS_PARAM_JSON) {
                baseValue = PrototypePollutionBodyScan.urlDecodeWithoutPlus(baseValue).trim();
            }

            if(insertionPoint.getInsertionPointType() == IScannerInsertionPoint.INS_PARAM_JSON) {
                attackReq = insertionPoint.buildRequest(nullifyInjection.getBytes());
            } else if(baseValue.startsWith("{") && PrototypePollutionBodyScan.isValidJson(baseValue)) {
                attackReq = baseRequestResponse.getRequest().clone();
                JsonElement attackJson = PrototypePollutionBodyScan.generateJson(baseValue, technique.getValue(), false);
                attackReq = Utilities.helpers.updateParameter(attackReq, PrototypePollutionBodyScan.createParameter(insertionPoint.getInsertionPointName(), attackJson.toString(),insertionPoint.getInsertionPointType()));
            } else {
                continue;
            }

            Resp attackResp = request(service, attackReq, MAX_RETRIES);

            if(attackResp.failed()) {
                continue;
            }

            if(attackType.equals("spacing")) {
                Resp baseResp = request(service, baseRequestResponse.getRequest(), MAX_RETRIES);
                String response = Utilities.getBody(baseResp.getReq().getResponse());
                if(hasSpacing(response)) {
                    byte[] nullifyAttackRequest;
                    if(insertionPoint.getInsertionPointType() == IScannerInsertionPoint.INS_PARAM_JSON) {
                        nullifyAttackRequest = insertionPoint.buildRequest(nullifyInjection.getBytes());
                    } else {
                        byte[] baseReq = baseRequestResponse.getRequest().clone();
                        JsonElement attackJson = PrototypePollutionBodyScan.generateJson(baseValue, technique.getValue(), true);
                        nullifyAttackRequest = Utilities.helpers.updateParameter(baseReq, PrototypePollutionBodyScan.createParameter(insertionPoint.getInsertionPointName(), attackJson.toString(),insertionPoint.getInsertionPointType()));
                    }
                    request(service, nullifyAttackRequest, MAX_RETRIES);
                    Resp nullifyResponse = request(service, baseRequestResponse.getRequest(), MAX_RETRIES);

                    if(nullifyResponse.failed()) {
                        continue;
                    }

                    String nullifyResponseStr = Utilities.getBody(nullifyResponse.getReq().getResponse());
                    if(!hasSpacing(nullifyResponseStr)) {
                        reportIssue("PP JSON spacing", DETAIL, "High", "Firm", ".", baseRequestResponse.getRequest(), attackResp, baseResp, nullifyResponse);
                    }
                }
            } else if(attackType.equals("status")) {
                Resp invalidJsonResp = makeInvalidJsonRequest(service, insertionPoint);
                if(hasStatusCode(510, invalidJsonResp)) {
                    byte[] nullifyAttackRequest;
                    if(insertionPoint.getInsertionPointType() == IScannerInsertionPoint.INS_PARAM_JSON) {
                        nullifyAttackRequest = insertionPoint.buildRequest(nullifyInjection.getBytes());
                    } else {
                        byte[] baseReq = baseRequestResponse.getRequest().clone();
                        JsonElement attackJson = PrototypePollutionBodyScan.generateJson(baseValue, technique.getValue(), true);
                        nullifyAttackRequest = Utilities.helpers.updateParameter(baseReq, PrototypePollutionBodyScan.createParameter(insertionPoint.getInsertionPointName(), attackJson.toString(),insertionPoint.getInsertionPointType()));
                    }
                    Resp nullifyAttackRequestResp = request(service, nullifyAttackRequest, MAX_RETRIES);

                    if(nullifyAttackRequestResp.failed()) {
                        continue;
                    }

                    Resp invalidJsonNullified = makeInvalidJsonRequest(service, insertionPoint);
                    if(!hasStatusCode(510, invalidJsonNullified)) {
                        reportIssue("PP JSON status", DETAIL, "High", "Firm", ".", baseRequestResponse.getRequest(), attackResp, invalidJsonResp, nullifyAttackRequestResp, invalidJsonNullified);
                    }
                }
            } else if(attackType.equals("options")) {
                Resp optionsResp = request(service, Utilities.setMethod(baseRequestResponse.getRequest(), "OPTIONS"), MAX_RETRIES);

                if(optionsResp.failed()) {
                    continue;
                }

                String allow = Utilities.getHeader(optionsResp.getReq().getResponse(), "Allow").toLowerCase();
                if(!allow.contains("head") && allow.length() > 0) {
                    byte[] nullifyAttackRequest;
                    if(insertionPoint.getInsertionPointType() == IScannerInsertionPoint.INS_PARAM_JSON) {
                        nullifyAttackRequest = insertionPoint.buildRequest(nullifyInjection.getBytes());
                    } else {
                        byte[] baseReq = baseRequestResponse.getRequest().clone();
                        JsonElement attackJson = PrototypePollutionBodyScan.generateJson(baseValue, technique.getValue(), true);
                        nullifyAttackRequest = Utilities.helpers.updateParameter(baseReq, PrototypePollutionBodyScan.createParameter(insertionPoint.getInsertionPointName(), attackJson.toString(),insertionPoint.getInsertionPointType()));
                    }
                    request(service, nullifyAttackRequest, MAX_RETRIES);
                    Resp nullifyAttackRequestResp = request(service, nullifyAttackRequest, MAX_RETRIES);

                    if(nullifyAttackRequestResp.failed()) {
                        continue;
                    }

                    Resp nullifyOptionsResp = request(service, Utilities.setMethod(baseRequestResponse.getRequest(), "OPTIONS"), MAX_RETRIES);

                    if(nullifyOptionsResp.failed()) {
                        continue;
                    }

                    String nullifiedAllow = Utilities.getHeader(nullifyOptionsResp.getReq().getResponse(), "Allow").toLowerCase();
                    if(nullifiedAllow.contains("head")) {
                        reportIssue("PP JSON head", DETAIL, "High", "Firm", ".", baseRequestResponse.getRequest(), attackResp, optionsResp, nullifyAttackRequestResp, nullifyOptionsResp);
                    }
                }
            } else if(attackType.equals("exposedHeaders")) {
                Resp baseResp = request(service, baseRequestResponse.getRequest(), MAX_RETRIES);

                if(baseResp.failed()) {
                    continue;
                }

                String accessControlExposeHeaders = Utilities.getHeader(baseResp.getReq().getResponse(), "Access-Control-Expose-Headers").toLowerCase();
                if(accessControlExposeHeaders.contains(CANARY)) {
                    byte[] nullifyAttackRequest;
                    if(insertionPoint.getInsertionPointType() == IScannerInsertionPoint.INS_PARAM_JSON) {
                        nullifyAttackRequest = insertionPoint.buildRequest(nullifyInjection.getBytes());
                    } else {
                        byte[] baseReq = baseRequestResponse.getRequest().clone();
                        JsonElement attackJson = PrototypePollutionBodyScan.generateJson(baseValue, technique.getValue(), true);
                        nullifyAttackRequest = Utilities.helpers.updateParameter(baseReq, PrototypePollutionBodyScan.createParameter(insertionPoint.getInsertionPointName(), attackJson.toString(),insertionPoint.getInsertionPointType()));
                    }
                    request(service, nullifyAttackRequest, MAX_RETRIES);
                    Resp nullifyAttackRequestResp = request(service, nullifyAttackRequest, MAX_RETRIES);

                    if(nullifyAttackRequestResp.failed()) {
                        continue;
                    }

                    Resp nullifyResp = request(service, baseRequestResponse.getRequest(), MAX_RETRIES);

                    if(nullifyResp.failed()) {
                        continue;
                    }

                    String nullifiedAccessControlExposeHeaders = Utilities.getHeader(nullifyResp.getReq().getResponse(), "Access-Control-Expose-Headers").toLowerCase();
                    if(!nullifiedAccessControlExposeHeaders.contains(CANARY)) {
                        reportIssue("PP JSON exposedHeaders", DETAIL, "High", "Firm", ".", baseRequestResponse.getRequest(), attackResp, baseResp, nullifyAttackRequestResp, nullifyAttackRequestResp, nullifyResp);
                    }
                }
            }
        }
    }

    private Resp makeInvalidJsonRequest(IHttpService service, IScannerInsertionPoint insertionPoint) {
        String invalidJson = "{";
        byte[] invalidJsonAttackRequest;
        if(insertionPoint.getInsertionPointType() == IScannerInsertionPoint.INS_PARAM_JSON) {
            invalidJsonAttackRequest = insertionPoint.buildRequest(invalidJson.getBytes());
        } else {
            invalidJsonAttackRequest = insertionPoint.buildRequest(PrototypePollutionBodyScan.urlEncodeWithoutPlus(invalidJson).getBytes());
        }
        return request(service, invalidJsonAttackRequest, MAX_RETRIES);
    }

    static Boolean hasSpacing(String response) {
        String responseStart = response.substring(0,response.length() > 20 ? 20 : response.length());
        Pattern regex = Pattern.compile("^\\s*[{\\[]\\s+", Pattern.CASE_INSENSITIVE);
        Matcher matcher = regex.matcher(responseStart);
        return matcher.find();
    }

    static Boolean hasStatusCode(Integer status, Resp response) {
        return response.getStatus() == status;
    }

    static void reportIssue(String title, String detail, String severity, String confidence, String remediation, byte[] baseBytes, Resp... requests) {
        IHttpRequestResponse base = requests[0].getReq();
        IHttpService service = base.getHttpService();
        ArrayList<IHttpRequestResponse> reqsToReport = new ArrayList();
        if (baseBytes != null) {
            Resp baseReq = new Resp(new Req(baseBytes, (byte[])null, service));
            reqsToReport.add(baseReq.getReq());
        }
        int len = requests.length;
        for(int i = 0; i < len; ++i) {
            Resp request = requests[i];
            reqsToReport.add(request.getReq());
        }
        Utilities.callbacks.addScanIssue(new CustomScanIssue(service, Utilities.getURL(base.getRequest(), service), reqsToReport.toArray(new IHttpRequestResponse[0]), title, detail, severity, confidence, remediation));
    }
}
