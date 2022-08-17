package burp;

import com.google.gson.*;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class PrototypePollutionBodyScan extends Scan {

    static final String DETAIL = "This application is vulnerable to Server side prototype pollution";
    static final String CANARY = "f1e3f7a9";
    static final Integer MAX_RETRIES = 1;

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
            put("blitz", new String[]{
                    "__proto__","{\"__proto__\":{}}","{\"__proto__\":\"xyz\"}"
            });
        }
    };

    PrototypePollutionBodyScan(String name) {
        super(name);
    }

    @Override
    public List<IScanIssue> doScan(byte[] baseReq, IHttpService service) {
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

    private byte[] createRequestAndBuildJson(String jsonString, byte[] baseReq, String[] currentTechnique, Boolean hasBody, Boolean nullify, IParameter param) {
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

    private byte[] createRequestFromJson(String jsonString, byte[] baseReq, Boolean hasBody, IParameter param) {
        byte[] request = baseReq.clone();
        if(hasBody) {
            request = Utilities.setBody(request, jsonString);
            request = Utilities.fixContentLength(request);
        }
        if(param != null) {
            request = Utilities.helpers.updateParameter(request, createParameter(param.getName(), jsonString,param.getType()));
        }
        return request;
    }

    static ArrayList<String[]> getAttackAndNullifyJsonStrings(String jsonString, String[] currentTechnique, String propertyRegex) {
        ArrayList<String[]> jsonList = new ArrayList<>();
        try {
            JsonElement json = new JsonParser().parse(jsonString);
            if(json.isJsonArray() || json.isJsonObject()) {
                traverseJsonGenerateJsonAttackAndNullifyStrings(json, currentTechnique, jsonList, json, propertyRegex);
            }
            return jsonList;
        } catch(JsonSyntaxException e) {
            Utilities.err("Invalid JSON:" + e);
            return null;
        }
    }

    static String processJsonElement(JsonElement e, JsonElement targetObject, String existingPropertyName, String newPropertyName, JsonElement value) {
        String output = "";
        if (e.isJsonArray()) {
            output += processJsonArray(e.getAsJsonArray(), targetObject, existingPropertyName, newPropertyName, value);
        } else if (e.isJsonNull()) {
            output += processJsonNull(e.getAsJsonNull());
        } else if (e.isJsonObject()) {
            output += processJsonObject(e.getAsJsonObject(), targetObject, existingPropertyName, newPropertyName, value);
        } else if (e.isJsonPrimitive()) {
            output += processJsonPrimitive(e.getAsJsonPrimitive());
        }
        return output;
    }

    static String processJsonArray(JsonArray a, JsonElement targetObject, String existingPropertyName, String newPropertyName, JsonElement value) {
        String output = "[";
        for (JsonElement e : a) {
            output += processJsonElement(e, targetObject, existingPropertyName, newPropertyName, value);
            output += ",";
        }
        output = removeLastChar(output);
        output += "]";
        return output;
    }

    static String processJsonNull(JsonNull n) {
        return "null";
    }

    static String processJsonObject(JsonObject o, JsonElement targetObject, String existingPropertyName, String newPropertyName, JsonElement newValue) {
        String output = "{";
        Set<Map.Entry<String, JsonElement>> members = o.entrySet();
        for (Map.Entry<String, JsonElement> element : members) {
            if(targetObject.getAsJsonObject() == o && element.getKey().equals(existingPropertyName)) {
                output += new JsonPrimitive(newPropertyName) + ":" + newValue;
            } else {
                output += new JsonPrimitive(element.getKey()) + ":" + processJsonElement(element.getValue(), targetObject, existingPropertyName, newPropertyName, newValue);
            }
            output += ",";
        }
        output = removeLastChar(output);
        output += "}";
        return output;
    }

    static String processJsonPrimitive(JsonPrimitive p) {
        return p.toString();
    }

    public static String removeLastChar(String s) {
        return (s == null || s.length() == 0) ? null : (s.substring(0, s.length() - 1));
    }

    static String generateJsonString(JsonElement fullObject, JsonElement targetObject, String existingPropertyName, String newPropertyName, JsonElement value) {
        return processJsonElement(fullObject, targetObject, existingPropertyName, newPropertyName, value);
    }

    static JsonElement traverseJsonGenerateJsonAttackAndNullifyStrings(JsonElement jsonElement, String[] currentTechnique, ArrayList<String[]> jsonList, JsonElement fullJsonElement, String propertyRegex) {
        if (jsonElement.isJsonNull()) {
            return null;
        }

        if (jsonElement.isJsonPrimitive()) {
            return null;
        }

        if (jsonElement.isJsonArray()) {
            JsonArray jsonArray = jsonElement.getAsJsonArray();
            if ( null != jsonArray) {
                for (int i=0;i<jsonArray.size();i++) {
                    jsonElement = traverseJsonGenerateJsonAttackAndNullifyStrings(jsonArray.get(i), currentTechnique, jsonList, fullJsonElement, propertyRegex);
                }
                if(jsonElement != null) {
                    return jsonElement;
                }
            }
            return null;
        }

        if (jsonElement.isJsonObject()) {
            JsonParser parser = new JsonParser();
            Set<Map.Entry<String, JsonElement>> jsonObjectEntrySet = jsonElement.getAsJsonObject().entrySet();
            for (Map.Entry<String, JsonElement> jsonEntry : jsonObjectEntrySet) {
                JsonElement originalJsonObject = jsonEntry.getValue();
                String existingPropertyName = jsonEntry.getKey();
                Pattern regex = Pattern.compile(propertyRegex, Pattern.CASE_INSENSITIVE);
                Matcher matcher = regex.matcher(existingPropertyName);
                if( matcher.find() ) {
                    for (int i = 0; i < currentTechnique.length; i += 3) {
                        String techniquePropertyName = currentTechnique[i];
                        String techniqueValue = currentTechnique[i + 1];
                        String nullifyValue = currentTechnique[i + 2];
                        jsonList.add(new String[]{generateJsonString(fullJsonElement, jsonElement, existingPropertyName, techniquePropertyName, parser.parse(techniqueValue)),generateJsonString(fullJsonElement, jsonElement, existingPropertyName, techniquePropertyName, parser.parse(nullifyValue))});
                        if (jsonEntry.getValue().isJsonArray()) {
                            JsonArray jsonArray = jsonEntry.getValue().getAsJsonArray();
                            if (jsonArray.size() == 1) {
                                JsonElement originalValue = jsonArray.get(0);
                                modifyArray(jsonArray, new JsonPrimitive(techniquePropertyName));
                                String attackArray = fullJsonElement.toString();
                                modifyArray(jsonArray, parser.parse(nullifyValue));
                                String nullifyArray = fullJsonElement.toString();
                                jsonList.add(new String[] { attackArray, nullifyArray });
                                modifyArray(originalJsonObject, originalValue);
                            }
                        }
                    }
                }
                traverseJsonGenerateJsonAttackAndNullifyStrings(jsonEntry.getValue(), currentTechnique, jsonList, fullJsonElement, propertyRegex);
            }
        }
        return null;
    }

    private static void modifyArray(JsonElement jsonElement, JsonElement newValue) {
        JsonArray jsonArray = jsonElement.getAsJsonArray();
        jsonArray.set(0, newValue);
    }

    public void doAttack(byte[] baseReq, String jsonString, IHttpService service, String[] currentTechnique, String attackType) {

        if(!jsonString.trim().startsWith("{") && !jsonString.trim().startsWith("[")) {
            return;
        }

        if(attackType.equals("blitz")) {
           ArrayList<String[]> jsonList = getAttackAndNullifyJsonStrings(jsonString, currentTechnique, "[.]");
           for (String[] json : jsonList) {
               String attackJsonString = json[0];
               String nullifyJsonString = json[1];

               byte[] attackRequest = baseReq.clone();
               attackRequest = Utilities.setBody(attackRequest, attackJsonString);
               attackRequest = Utilities.fixContentLength(attackRequest);
               if(attackRequest != null) {
                   doJsonAttack(baseReq, service, attackRequest, attackType, jsonString, currentTechnique, true, null, nullifyJsonString);
               }
           }
        } else {
            JsonElement attackJson = generateJson(jsonString, currentTechnique, false);
            byte[] attackRequest = baseReq.clone();
            if (attackJson != null && !attackJson.isJsonNull()) {
                attackRequest = Utilities.setBody(attackRequest, attackJson.toString());
                attackRequest = Utilities.fixContentLength(attackRequest);
                doJsonAttack(baseReq, service, attackRequest, attackType, jsonString, currentTechnique, true, null, null);
            }
        }
     }

     private void doJsonAttack(byte[] baseReq, IHttpService service, byte[] attackRequest, String attackType, String jsonString, String[] currentTechnique, Boolean hasBody, IParameter param, String nullifiedJsonString) {
         Resp attackResp = request(service, attackRequest, MAX_RETRIES);

         if(attackResp.failed()) {
             return;
         }
         Utilities.out("Doing JSON"+(hasBody ? " Body " : " ") + attackType + " attack");
         if(attackType.equals("blitz")) {
             String response = Utilities.getBody(attackResp.getReq().getResponse());
             Boolean hasImmutable = responseHas(response, "Immutable.{1,10}prototype.{1,10}object");
             Boolean hasStatusCode500 = hasStatusCode(500, attackResp);
             if(hasImmutable || hasStatusCode500) {
                 byte[] nullifyAttackRequest = createRequestFromJson(nullifiedJsonString, baseReq, hasBody, param);
                 Resp nullifyResponse = request(service, nullifyAttackRequest, MAX_RETRIES);

                 if(nullifyResponse.failed()) {
                     return;
                 }

                 String nullifyResponseStr = Utilities.getBody(nullifyResponse.getReq().getResponse());
                 if((hasImmutable && !responseHas(nullifyResponseStr, "Immutable.{1,10}prototype.{1,10}object")) || (hasStatusCode500 && !hasStatusCode(500, nullifyResponse))) {
                     reportIssue("PP JSON Blitz", DETAIL, "High", "Firm", ".", baseReq, attackResp, nullifyResponse);
                 }
             }
         } else if(attackType.equals("spacing")) {
             Resp baseResp = request(service, baseReq, MAX_RETRIES);

             if(baseResp.failed()) {
                 return;
             }

             String response = Utilities.getBody(baseResp.getReq().getResponse());
             if(hasSpacing(response)) {
                 byte[] nullifyAttackRequest = createRequestAndBuildJson(jsonString, baseReq, currentTechnique, hasBody, true, param);
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
                 byte[] nullifyAttackRequest = createRequestAndBuildJson(jsonString, baseReq, currentTechnique, hasBody, true, param);
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
                 byte[] nullifyAttackRequest = createRequestAndBuildJson(jsonString, baseReq, currentTechnique, hasBody, true, param);
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
                 byte[] nullifyAttackRequest = createRequestAndBuildJson(jsonString, baseReq, currentTechnique, hasBody, true, param);
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

    static Boolean responseHas(String response, String pattern) {
        Pattern regex = Pattern.compile(pattern, Pattern.CASE_INSENSITIVE);
        Matcher matcher = regex.matcher(response);
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

    public static byte[] addJsonBodyParameter(byte[] req, String propertyName, String propertyValue) {
        byte[] modifiedReq;
        String body = Utilities.getBody(req);
        if (body.trim().startsWith("{") && PrototypePollutionBodyScan.isValidJson(body)) {
            try {
                JsonParser parser = new JsonParser();
                JsonElement jsonElement = parser.parse(body);
                jsonElement = traverseJsonTreeAndInject(jsonElement, new String[]{propertyName, propertyValue}, false);
                modifiedReq = Utilities.setBody(req,jsonElement.toString());
                return modifiedReq;
            } catch (JsonSyntaxException e) {
                Utilities.err("Invalid JSON:" + e);
            }
        }
        return null;
    }

    static Boolean hasStatusCode(Integer status, Resp response) {
        return response.getStatus() == status;
    }

    private Resp makeInvalidJsonRequest(IHttpService service, byte[] req) {
        String method = Utilities.getMethod(req);
        String contentTypeText = "Content-Type";
        String contentType = Utilities.getHeader(req, contentTypeText);
        if(contentType.length() == 0) {
            contentTypeText = "content-type";
            contentType = Utilities.getHeader(req, contentTypeText);
        }
        if(contentType.length() == 0 || contentType.contains("text/html") || contentType.contains("application/x-www-form-urlencoded")) {
            req = Utilities.addOrReplaceHeader(req, contentTypeText, "application/json");
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