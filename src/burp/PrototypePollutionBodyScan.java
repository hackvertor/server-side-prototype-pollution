package burp;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class PrototypePollutionBodyScan extends Scan {

    private final String DETAIL = "This application is vulnerable to Server side prototype pollution";
    static final String CANARY = "f1e3f7a9";
    private final Integer MAX_RETRIES = 3;

    static final Map<String, String[]> jsonTechniques = new HashMap<String, String[]>()
    {
        {
            put("spacing", new String[]{
                    "__proto__","{\"json spaces\":\" \"}","{\"json spaces\":\"\"}"
            });
            put("options", new String[]{
                    "__proto__","{\"head\":true}","{\"head\":false}"
            });
            put("status", new String[]{
                    "__proto__","{\"status\":510}","{\"status\":0}"
            });
            put("exposedHeaders", new String[]{
                    "__proto__","{\"exposedHeaders\":[\""+CANARY+"\"]}","{\"exposedHeaders\":null}"
            });
        }
    };

    PrototypePollutionBodyScan(String name) {
        super(name);
    }

    @Override
    List<IScanIssue> doScan(byte[] baseReq, IHttpService service) {
        for (Map.Entry<String, String[]> technique : jsonTechniques.entrySet()) {
            doAttack(baseReq, Utilities.getBody(baseReq), service, technique.getValue(), technique.getKey());
        }

        return null;
    }

    static JsonElement generateJson(String jsonString, String[] currentTechnique, Boolean nullify) {
        JsonParser parser = new JsonParser();
        try {
            JsonElement jsonElement = parser.parse(jsonString);
            JsonElement json = traverseJsonTreeAndInject(deepJsonClone(jsonElement), currentTechnique, nullify);
            return json;
        } catch(JsonSyntaxException e) {
            Utilities.err("Invalid JSON:" + e);
            return null;
        }
    }

    private byte[] createRequest(String jsonString, byte[] baseReq, String[] currentTechnique, String attackType, Boolean hasBody, Boolean nullify, IParameter param) {
        JsonElement json = generateJson(jsonString, currentTechnique, nullify);
        byte[] request = baseReq.clone();
        if(hasBody) {
            request = Utilities.setBody(request, json.toString());
            request = Utilities.fixContentLength(request);
        }
        if(param != null) {
            request = Utilities.helpers.updateParameter(request, createParameter(param.getName(), json.toString(),param.getType()));
        }
        return request;
    }

    private void doAttack(byte[] baseReq, String jsonString, IHttpService service,  String[] currentTechnique, String attackType) {

        if(!jsonString.trim().startsWith("{")) {
            return;
        }

        JsonElement attackJson = generateJson(jsonString, currentTechnique, false);

        byte[] attackRequest = baseReq.clone();

        if(attackJson != null && !attackJson.isJsonNull()) {
            attackRequest = Utilities.setBody(attackRequest, attackJson.toString());
            attackRequest = Utilities.fixContentLength(attackRequest);
            doJsonAttack(baseReq, service, attackRequest, attackType, jsonString, currentTechnique, true, null);
        }
     }

     private void doJsonAttack(byte[] baseReq, IHttpService service, byte[] attackRequest, String attackType, String jsonString, String[] currentTechnique, Boolean hasBody, IParameter param) {
         Resp attackResp = request(service, attackRequest, MAX_RETRIES);

         if(attackResp.failed()) {
             return;
         }

         if(attackType.equals("spacing")) {
             Resp baseResp = request(service, baseReq, MAX_RETRIES);

             if(baseResp.failed()) {
                 return;
             }

             String response = Utilities.getBody(baseResp.getReq().getResponse());
             if(hasSpacing(response)) {
                 byte[] nullifyAttackRequest = createRequest(jsonString, baseReq, currentTechnique, attackType, hasBody, true, param);
                 request(service, nullifyAttackRequest, MAX_RETRIES);
                 Resp nullifyResponse = request(service, baseReq, MAX_RETRIES);

                 if(nullifyResponse.failed()) {
                     return;
                 }

                 String nullifyResponseStr = Utilities.getBody(nullifyResponse.getReq().getResponse());
                 if(!hasSpacing(nullifyResponseStr)) {
                     reportIssue("PP JSON spacing", DETAIL, "High", "Firm", ".", baseReq, attackResp, baseResp, nullifyResponse);
                 }
             }
         } else if(attackType.equals("status")) {
             Resp invalidJsonResp = makeInvalidJsonRequest(service, baseReq);
             if(hasStatusCode(510, invalidJsonResp)) {
                 byte[] nullifyAttackRequest = createRequest(jsonString, baseReq, currentTechnique, attackType, hasBody, true, param);
                 request(service, nullifyAttackRequest, MAX_RETRIES);
                 Resp nullifyAttackRequestResp = request(service, nullifyAttackRequest, MAX_RETRIES);

                 if(nullifyAttackRequestResp.failed()) {
                     return;
                 }

                 Resp invalidJsonNullified = makeInvalidJsonRequest(service, baseReq);
                 if(!hasStatusCode(510, invalidJsonNullified)) {
                     reportIssue("PP JSON status", DETAIL, "High", "Firm", ".", baseReq, attackResp, invalidJsonResp, nullifyAttackRequestResp, invalidJsonNullified);
                 }
             }
         } else if(attackType.equals("options")) {
             Resp optionsResp = request(service, Utilities.setMethod(baseReq, "OPTIONS"), MAX_RETRIES);

             if(optionsResp.failed()) {
                 return;
             }

             String allow = Utilities.getHeader(optionsResp.getReq().getResponse(), "Allow").toLowerCase();
             if(!allow.contains("head") && allow.length() > 0) {
                 byte[] nullifyAttackRequest = createRequest(jsonString, baseReq, currentTechnique, attackType, hasBody, true, param);
                 request(service, nullifyAttackRequest, MAX_RETRIES);
                 Resp nullifyAttackRequestResp = request(service, nullifyAttackRequest, MAX_RETRIES);

                 if(nullifyAttackRequestResp.failed()) {
                     return;
                 }

                 Resp nullifyOptionsResp = request(service, Utilities.setMethod(baseReq, "OPTIONS"), MAX_RETRIES);

                 if(nullifyOptionsResp.failed()) {
                     return;
                 }

                 String nullifiedAllow = Utilities.getHeader(nullifyOptionsResp.getReq().getResponse(), "Allow").toLowerCase();
                 if(nullifiedAllow.contains("head")) {
                     reportIssue("PP JSON options", DETAIL, "High", "Firm", ".", baseReq, attackResp, optionsResp, nullifyAttackRequestResp, nullifyOptionsResp);
                 }
             }
         } else if(attackType.equals("exposedHeaders")) {
             Resp baseResp = request(service, baseReq, MAX_RETRIES);

             if(baseResp.failed()) {
                 return;
             }

             String accessControlExposeHeaders = Utilities.getHeader(baseResp.getReq().getResponse(), "Access-Control-Expose-Headers").toLowerCase();
             if(accessControlExposeHeaders.contains(CANARY)) {
                 byte[] nullifyAttackRequest = createRequest(jsonString, baseReq, currentTechnique, attackType, hasBody, true, param);
                 request(service, nullifyAttackRequest, MAX_RETRIES);
                 Resp nullifyAttackRequestResp = request(service, nullifyAttackRequest, MAX_RETRIES);

                 if(nullifyAttackRequestResp.failed()) {
                     return;
                 }

                 Resp nullifyResp = request(service, baseReq,MAX_RETRIES);

                 if(nullifyResp.failed()) {
                     return;
                 }

                 String nullifiedAccessControlExposeHeaders = Utilities.getHeader(nullifyResp.getReq().getResponse(), "Access-Control-Expose-Headers").toLowerCase();
                 if(!nullifiedAccessControlExposeHeaders.contains(CANARY)) {
                     reportIssue("PP JSON exposedHeaders", DETAIL, "High", "Firm", ".", baseReq, attackResp, baseResp, nullifyAttackRequestResp, nullifyAttackRequestResp, nullifyResp);
                 }
             }
         }
     }

     static Boolean isValidJson(String json) {
         JsonParser parser = new JsonParser();
         try {
             parser.parse(json);
             return true;
         } catch(JsonSyntaxException e) {
             Utilities.err("Invalid JSON:" + e);
             return false;
         }
     }

    static Boolean hasSpacing(String response) {
        String responseStart = response.substring(0,response.length() > 20 ? 20 : response.length());
        Pattern regex = Pattern.compile("^\\s*[{\\[]\\s+", Pattern.CASE_INSENSITIVE);
        Matcher matcher = regex.matcher(responseStart);
        return matcher.find();
    }

    static JsonElement deepJsonClone(JsonElement jsonElement) {
        try {
            JsonParser parser = new JsonParser();
            return parser.parse(jsonElement.toString());
        } catch(JsonSyntaxException e) {
            Utilities.err("Failed to clone object");
            return null;
        }
    }

    static JsonElement traverseJsonTreeAndInject(JsonElement jsonElement, String[] currentTechnique, Boolean nullify) {
        if (jsonElement.isJsonNull()) {
            return jsonElement;
        }

        if (jsonElement.isJsonPrimitive()) {
            return jsonElement;
        }

        if (jsonElement.isJsonArray()) {
            JsonArray jsonArray = jsonElement.getAsJsonArray();
            if ( null != jsonArray) {
                for (int i=0;i<jsonArray.size();i++) {
                    jsonArray.set(i,traverseJsonTreeAndInject(jsonArray.get(i), currentTechnique, nullify));
                }
            }
            return jsonArray;
        }

        if (jsonElement.isJsonObject()) {
            Set<Map.Entry<String, JsonElement>> jsonObjectEntrySet = jsonElement.getAsJsonObject().entrySet();
            for (Map.Entry<String, JsonElement> jsonEntry : jsonObjectEntrySet) {
                traverseJsonTreeAndInject(jsonEntry.getValue(), currentTechnique, nullify);
            }

            for(int i=0;i<currentTechnique.length; i+=3) {
                String techniquePropertyName = currentTechnique[i];
                String techniqueValue = currentTechnique[!nullify?i+1:i+2];
                JsonParser parser = new JsonParser();
                jsonElement.getAsJsonObject().add(techniquePropertyName, parser.parse(techniqueValue));
            }
        }
        return jsonElement;
    }

    static IParameter createParameter(String paramName, String paramValue, byte insertionPointType) {
        return Utilities.helpers.buildParameter(urlEncodeWithoutPlus(paramName), urlEncodeWithoutPlus(paramValue), insertionPointType);
    }

    static String urlDecodeWithoutPlus(String encoded) {
        return Utilities.helpers.urlDecode(encoded.replaceAll("\\+", "%2b"));
    }

    static String urlEncodeWithoutPlus(String unEncoded) {
        return Utilities.helpers.urlEncode(unEncoded).replaceAll("\\+", "%20");
    }

    static Boolean hasStatusCode(Integer status, Resp response) {
        return response.getStatus() == status;
    }

    private Resp makeInvalidJsonRequest(IHttpService service, byte[] req) {
        String method = Utilities.getMethod(req);
        String contentType = Utilities.getHeader(req, "Content-Type");
        if(contentType.length() == 0 || contentType.contains("text/html") || contentType.contains("application/x-www-form-urlencoded")) {
            req = Utilities.addOrReplaceHeader(req, "Content-Type", "application/json");
        }
        req = Utilities.addOrReplaceHeader(req, "Content-Length", "0");
        req = Utilities.setBody(req, method.equalsIgnoreCase("get") ? "\n{" : "{");
        req = Utilities.fixContentLength(req);
        return request(service, req, MAX_RETRIES);
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