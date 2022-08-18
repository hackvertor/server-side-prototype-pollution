package burp;

import com.google.gson.JsonElement;

import java.util.List;
import java.util.Map;

public class PrototypePollutionParamScan extends ParamScan {

    public PrototypePollutionParamScan(String name) {
        super(name);
    }

    @Override
    List<IScanIssue> doScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        Utilities.out("--Running param scan--");
        injectInsertionPoint(baseRequestResponse, insertionPoint, PrototypePollutionBodyScan.jsonTechniques);
        return null;
    }

    public void injectInsertionPoint(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint, Map<String, String[]> techniques) {
        IHttpService service = baseRequestResponse.getHttpService();
        for (Map.Entry<String, String[]> technique : techniques.entrySet()) {
            String attackType = technique.getKey();
            String attackInjection = technique.getValue()[1];
            String nullifyInjection = technique.getValue()[2];
            String baseValue = insertionPoint.getBaseValue();
            byte[] attackReq;

            if (insertionPoint.getInsertionPointType() != IScannerInsertionPoint.INS_PARAM_JSON) {
                baseValue = PrototypePollutionBodyScan.urlDecodeWithoutPlus(baseValue).trim();
            }

            if (insertionPoint.getInsertionPointType() == IScannerInsertionPoint.INS_PARAM_JSON) {
                attackReq = insertionPoint.buildRequest(attackInjection.getBytes());
            } else if (baseValue.trim().startsWith("{") && PrototypePollutionBodyScan.isValidJson(baseValue)) {
                attackReq = baseRequestResponse.getRequest().clone();
                JsonElement attackJson = PrototypePollutionBodyScan.generateJson(baseValue, technique.getValue(), false);
                attackReq = Utilities.helpers.updateParameter(attackReq, PrototypePollutionBodyScan.createParameter(insertionPoint.getInsertionPointName(), attackJson.toString(), insertionPoint.getInsertionPointType()));
            } else {
                continue;
            }

            Resp attackResp = request(service, attackReq, PrototypePollutionBodyScan.MAX_RETRIES);

            if (attackResp.failed()) {
                continue;
            }

            Utilities.out("Doing param scan " + attackType + " attack");

            if(attackType.equals("blitz")) {
                byte[] req = baseRequestResponse.getRequest();
                Resp baseResp = request(service, req, PrototypePollutionBodyScan.MAX_RETRIES);
                String response = Utilities.getBody(attackResp.getReq().getResponse());
                Boolean hasImmutable = PrototypePollutionBodyScan.responseHas(response, "Immutable.{1,10}prototype.{1,10}object");
                Boolean hasStatusCode500 = PrototypePollutionBodyScan.hasStatusCode(500, attackResp);
                if(hasImmutable || hasStatusCode500) {
                    byte[] nullifyAttackRequest;
                    if(insertionPoint.getInsertionPointType() == IScannerInsertionPoint.INS_PARAM_JSON) {
                        nullifyAttackRequest = insertionPoint.buildRequest(nullifyInjection.getBytes());
                    } else {
                        byte[] baseReq = baseRequestResponse.getRequest().clone();
                        JsonElement attackJson = PrototypePollutionBodyScan.generateJson(baseValue, technique.getValue(), true);
                        nullifyAttackRequest = Utilities.helpers.updateParameter(baseReq, PrototypePollutionBodyScan.createParameter(insertionPoint.getInsertionPointName(), attackJson.toString(),insertionPoint.getInsertionPointType()));
                    }
                    request(service, nullifyAttackRequest, PrototypePollutionBodyScan.MAX_RETRIES);
                    Resp nullifyResponse = request(service, baseRequestResponse.getRequest(), PrototypePollutionBodyScan.MAX_RETRIES);

                    if(nullifyResponse.failed()) {
                        continue;
                    }

                    String nullifyResponseStr = Utilities.getBody(nullifyResponse.getReq().getResponse());
                    if((hasImmutable && !PrototypePollutionBodyScan.responseHas(nullifyResponseStr, "Immutable.{1,10}prototype.{1,10}object")) || (hasStatusCode500 && !PrototypePollutionBodyScan.hasStatusCode(500, nullifyResponse))) {
                        PrototypePollutionBodyScan.reportIssue("PP JSON Blitz", PrototypePollutionBodyScan.DETAIL, "High", "Firm", ".", baseRequestResponse.getRequest(), attackResp, baseResp, nullifyResponse);
                    }
                }
            } else if(attackType.equals("spacing")) {
                byte[] req;
                if(baseValue.equals("{}")) {
                    req = baseRequestResponse.getRequest().clone();
                    req = Utilities.helpers.updateParameter(req, PrototypePollutionBodyScan.createParameter(insertionPoint.getInsertionPointName(), "{\"test\":\"test\"}", insertionPoint.getInsertionPointType()));
                } else {
                    req = baseRequestResponse.getRequest();
                }
                Resp baseResp = request(service, req, PrototypePollutionBodyScan.MAX_RETRIES);
                String response = Utilities.getBody(baseResp.getReq().getResponse());
                if(PrototypePollutionBodyScan.hasSpacing(response)) {
                    byte[] nullifyAttackRequest;
                    if(insertionPoint.getInsertionPointType() == IScannerInsertionPoint.INS_PARAM_JSON) {
                        nullifyAttackRequest = insertionPoint.buildRequest(nullifyInjection.getBytes());
                    } else {
                        byte[] baseReq = baseRequestResponse.getRequest().clone();
                        JsonElement attackJson = PrototypePollutionBodyScan.generateJson(baseValue, technique.getValue(), true);
                        nullifyAttackRequest = Utilities.helpers.updateParameter(baseReq, PrototypePollutionBodyScan.createParameter(insertionPoint.getInsertionPointName(), attackJson.toString(),insertionPoint.getInsertionPointType()));
                    }
                    request(service, nullifyAttackRequest, PrototypePollutionBodyScan.MAX_RETRIES);
                    Resp nullifyResponse = request(service, baseRequestResponse.getRequest(), PrototypePollutionBodyScan.MAX_RETRIES);

                    if(nullifyResponse.failed()) {
                        continue;
                    }

                    String nullifyResponseStr = Utilities.getBody(nullifyResponse.getReq().getResponse());
                    if(!PrototypePollutionBodyScan.hasSpacing(nullifyResponseStr)) {
                        PrototypePollutionBodyScan.reportIssue("PP JSON spacing", PrototypePollutionBodyScan.DETAIL, "High", "Firm", ".", baseRequestResponse.getRequest(), attackResp, baseResp, nullifyResponse);
                    }
                }
            } else if(attackType.equals("status")) {
                Resp invalidJsonResp = makeInvalidJsonRequest(service, insertionPoint);
                if(PrototypePollutionBodyScan.hasStatusCode(510, invalidJsonResp)) {
                    byte[] nullifyAttackRequest;
                    if(insertionPoint.getInsertionPointType() == IScannerInsertionPoint.INS_PARAM_JSON) {
                        nullifyAttackRequest = insertionPoint.buildRequest(nullifyInjection.getBytes());
                    } else {
                        byte[] baseReq = baseRequestResponse.getRequest().clone();
                        JsonElement attackJson = PrototypePollutionBodyScan.generateJson(baseValue, technique.getValue(), true);
                        nullifyAttackRequest = Utilities.helpers.updateParameter(baseReq, PrototypePollutionBodyScan.createParameter(insertionPoint.getInsertionPointName(), attackJson.toString(),insertionPoint.getInsertionPointType()));
                    }
                    Resp nullifyAttackRequestResp = request(service, nullifyAttackRequest, PrototypePollutionBodyScan.MAX_RETRIES);

                    if(nullifyAttackRequestResp.failed()) {
                        continue;
                    }

                    Resp invalidJsonNullified = makeInvalidJsonRequest(service, insertionPoint);
                    if(!PrototypePollutionBodyScan.hasStatusCode(510, invalidJsonNullified)) {
                        PrototypePollutionBodyScan.reportIssue("PP JSON status", PrototypePollutionBodyScan.DETAIL, "High", "Firm", ".", baseRequestResponse.getRequest(), attackResp, invalidJsonResp, nullifyAttackRequestResp, invalidJsonNullified);
                    }
                }
            } else if(attackType.equals("options")) {
                Resp optionsResp = request(service, Utilities.setMethod(baseRequestResponse.getRequest(), "OPTIONS"), PrototypePollutionBodyScan.MAX_RETRIES);

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
                    request(service, nullifyAttackRequest, PrototypePollutionBodyScan.MAX_RETRIES);
                    Resp nullifyAttackRequestResp = request(service, nullifyAttackRequest, PrototypePollutionBodyScan.MAX_RETRIES);

                    if(nullifyAttackRequestResp.failed()) {
                        continue;
                    }

                    Resp nullifyOptionsResp = request(service, Utilities.setMethod(baseRequestResponse.getRequest(), "OPTIONS"), PrototypePollutionBodyScan.MAX_RETRIES);

                    if(nullifyOptionsResp.failed()) {
                        continue;
                    }

                    String nullifiedAllow = Utilities.getHeader(nullifyOptionsResp.getReq().getResponse(), "Allow").toLowerCase();
                    if(nullifiedAllow.contains("head")) {
                        PrototypePollutionBodyScan.reportIssue("PP JSON options", PrototypePollutionBodyScan.DETAIL, "High", "Firm", ".", baseRequestResponse.getRequest(), attackResp, optionsResp, nullifyAttackRequestResp, nullifyOptionsResp);
                    }
                }
            } else if(attackType.equals("exposedHeaders")) {
                Resp baseResp = request(service, baseRequestResponse.getRequest(), PrototypePollutionBodyScan.MAX_RETRIES);

                if(baseResp.failed()) {
                    continue;
                }

                String accessControlExposeHeaders = Utilities.getHeader(baseResp.getReq().getResponse(), "Access-Control-Expose-Headers").toLowerCase();
                if(accessControlExposeHeaders.contains(PrototypePollutionBodyScan.CANARY)) {
                    byte[] nullifyAttackRequest;
                    if(insertionPoint.getInsertionPointType() == IScannerInsertionPoint.INS_PARAM_JSON) {
                        nullifyAttackRequest = insertionPoint.buildRequest(nullifyInjection.getBytes());
                    } else {
                        byte[] baseReq = baseRequestResponse.getRequest().clone();
                        JsonElement attackJson = PrototypePollutionBodyScan.generateJson(baseValue, technique.getValue(), true);
                        nullifyAttackRequest = Utilities.helpers.updateParameter(baseReq, PrototypePollutionBodyScan.createParameter(insertionPoint.getInsertionPointName(), attackJson.toString(),insertionPoint.getInsertionPointType()));
                    }
                    request(service, nullifyAttackRequest, PrototypePollutionBodyScan.MAX_RETRIES);
                    Resp nullifyAttackRequestResp = request(service, nullifyAttackRequest, PrototypePollutionBodyScan.MAX_RETRIES);

                    if(nullifyAttackRequestResp.failed()) {
                        continue;
                    }

                    Resp nullifyResp = request(service, baseRequestResponse.getRequest(), PrototypePollutionBodyScan.MAX_RETRIES);

                    if(nullifyResp.failed()) {
                        continue;
                    }

                    String nullifiedAccessControlExposeHeaders = Utilities.getHeader(nullifyResp.getReq().getResponse(), "Access-Control-Expose-Headers").toLowerCase();
                    if(!nullifiedAccessControlExposeHeaders.contains(PrototypePollutionBodyScan.CANARY)) {
                        PrototypePollutionBodyScan.reportIssue("PP JSON exposedHeaders", PrototypePollutionBodyScan.DETAIL, "High", "Firm", ".", baseRequestResponse.getRequest(), attackResp, baseResp, nullifyAttackRequestResp, nullifyAttackRequestResp, nullifyResp);
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
        return request(service, invalidJsonAttackRequest, PrototypePollutionBodyScan.MAX_RETRIES);
    }
}
