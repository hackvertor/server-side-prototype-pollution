package burp;

import com.google.gson.JsonElement;

import java.util.List;
import java.util.Map;

public class PrototypePollutionAsyncParamScan extends ParamScan {
    public PrototypePollutionAsyncParamScan(String name) {
        super(name);
    }

    @Override
    List<IScanIssue> doScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        Utilities.out("--Running async param scan--");
        injectInsertionPoint(baseRequestResponse, insertionPoint, PrototypePollutionAsyncBodyScan.asyncTechniques);
        return null;
    }

    public void injectInsertionPoint(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint, Map<String, String[]> techniques) {
        IHttpService service = baseRequestResponse.getHttpService();
        for (Map.Entry<String, String[]> technique : techniques.entrySet()) {
            String attackType = technique.getKey();
            String attackInjection = technique.getValue()[1];
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
            Utilities.out("Doing async param scan " + attackType + " attack");
            request(service, attackReq, PrototypePollutionBodyScan.MAX_RETRIES);
        }
    }
}
