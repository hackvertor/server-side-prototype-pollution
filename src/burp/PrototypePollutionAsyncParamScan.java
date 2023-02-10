package burp;

import com.google.gson.JsonElement;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class PrototypePollutionAsyncParamScan extends ParamScan {
    public PrototypePollutionAsyncParamScan(String name) {
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

    @Override
    List<IScanIssue> doScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        if(Utilities.globalSettings.getBoolean("async technique")) {
            if (Utilities.isBurpPro()) {
                Utilities.out("--Running async param scan--");
                injectInsertionPoint(baseRequestResponse, insertionPoint, PrototypePollutionAsyncBodyScan.asyncTechniques);
            } else {
                Utilities.err("Burp Collaborator is not supported in the community edition");
            }
        }
        return null;
    }

    public void injectInsertionPoint(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint, Map<String, String[]> techniques) {
        IHttpService service = baseRequestResponse.getHttpService();
        for (Map.Entry<String, String[]> technique : techniques.entrySet()) {
            if(!PrototypePollutionBodyScan.shouldUseTechnique(technique)) {
                continue;
            }
            String attackType = technique.getKey();
            String attackInjection = technique.getValue()[1];
            ArrayList<String> collabPayloads = new ArrayList<>();
            String[] vector = new String[] {
                    technique.getValue()[0],
                    PrototypePollutionAsyncBodyScan.replacePlaceholderWithCollaboratorPayload(attackInjection, collabPayloads)
            };
            String baseValue = insertionPoint.getBaseValue();
            byte[] attackReq;

            if (insertionPoint.getInsertionPointType() != IScannerInsertionPoint.INS_PARAM_JSON) {
                baseValue = PrototypePollutionBodyScan.urlDecodeWithoutPlus(baseValue).trim();
            }

            if (insertionPoint.getInsertionPointType() == IScannerInsertionPoint.INS_PARAM_JSON) {
                attackReq = insertionPoint.buildRequest(attackInjection.getBytes());
            } else if (baseValue.trim().startsWith("{") && PrototypePollutionBodyScan.isValidJson(baseValue)) {
                attackReq = baseRequestResponse.getRequest().clone();
                JsonElement attackJson = PrototypePollutionBodyScan.generateJson(baseValue, vector, false);
                attackReq = Utilities.helpers.updateParameter(attackReq, PrototypePollutionBodyScan.createParameter(insertionPoint.getInsertionPointName(), attackJson.toString(), insertionPoint.getInsertionPointType()));
            } else {
                continue;
            }
            Utilities.out("Doing async param scan " + attackType + " attack");
            Resp reqResp = request(service, attackReq, PrototypePollutionBodyScan.MAX_RETRIES);
            int reqId = -1;
            if(collabPayloads.size() > 0) {
                if(reqResp != null) {
                    reqId = BurpExtender.collab.addRequest(new MetaRequest(reqResp.getReq()));
                }
            }
            for (String collabPayload : collabPayloads) {
                if(reqId > 0) {
                    BurpExtender.collab.addCollboratorPayload(collabPayload, reqId);
                }
            }
        }
    }
}
