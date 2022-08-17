package burp;

import java.util.ArrayList;
import java.util.List;

public class PrototypePollutionAddJSPropertyScan extends Scan {

    PrototypePollutionAddJSPropertyScan(String name) {
        super(name);
        scanSettings.register("vulnerable response regex", PrototypePollutionJSPropertyParamScan.DEFAULT_RESPONSE_REGEX, "Regex used to see if the server behaves differently");
        scanSettings.register("valid property name", PrototypePollutionJSPropertyParamScan.DEFAULT_VALID_PROPERTY, "Valid property name that causes behaviour difference");
        scanSettings.register("valid property value", PrototypePollutionJSPropertyParamScan.DEFAULT_VALID_PROPERTY_VALUE, "Valid property value that causes behaviour difference");
        scanSettings.register("invalid property name", PrototypePollutionJSPropertyParamScan.DEFAULT_INVALID_PROPERTY, "Invalid property name that doesn't trigger different behaviour");
        scanSettings.register("invalid property value", PrototypePollutionJSPropertyParamScan.DEFAULT_INVALID_PROPERTY_VALUE, "Invalid property value that doesn't trigger different behaviour");
    }

    @Override
    List<IScanIssue> doScan(byte[] baseReq, IHttpService service) {
        injectInsertionPoint(baseReq, service, IScannerInsertionPoint.INS_PARAM_COOKIE);
        injectInsertionPoint(baseReq, service, IScannerInsertionPoint.INS_PARAM_BODY);
        injectInsertionPoint(baseReq, service, IScannerInsertionPoint.INS_PARAM_URL);
        injectInsertionPoint(baseReq, service, IScannerInsertionPoint.INS_PARAM_JSON);
        return null;
    }

    void scanJsonBody(byte[] baseReq, IHttpService service, String propertyRegex) {
        String validProperty = Utilities.globalSettings.getString("valid property name");
        String validPropertyValue = Utilities.globalSettings.getString("valid property value");
        String invalidPropertyValue = Utilities.globalSettings.getString("invalid property value");
        String jsonString = Utilities.getBody(baseReq);
        String[] currentTechnique = new String[]{validProperty,validPropertyValue,invalidPropertyValue};
        ArrayList<String[]> jsonList = PrototypePollutionBodyScan.getAttackAndNullifyJsonStrings(jsonString, currentTechnique, propertyRegex);
        for (String[] json : jsonList) {
            String attackJsonString = json[0];
            String nullifyJsonString = json[1];
            byte[] attackRequest = baseReq.clone();
            attackRequest = Utilities.setBody(attackRequest, attackJsonString);
            attackRequest = Utilities.fixContentLength(attackRequest);

            byte[] nullifyRequest = baseReq.clone();
            nullifyRequest = Utilities.setBody(nullifyRequest, nullifyJsonString);
            nullifyRequest = Utilities.fixContentLength(nullifyRequest);
            doAttack(baseReq, service, attackRequest, nullifyRequest);
        }
    }

    public void injectInsertionPoint(byte[] baseReq, IHttpService service, byte insertionPointType) {

        String validProperty = Utilities.globalSettings.getString("valid property name");
        String validPropertyValue = Utilities.globalSettings.getString("valid property value");
        String invalidProperty = Utilities.globalSettings.getString("invalid property name");
        String invalidPropertyValue = Utilities.globalSettings.getString("invalid property value");
        byte[] attackReq;
        if(insertionPointType == IScannerInsertionPoint.INS_PARAM_JSON) {
            scanJsonBody(baseReq, service, ".*");
        } else {
            IParameter parameter = Utilities.helpers.buildParameter(PrototypePollutionBodyScan.urlEncodeWithoutPlus(validProperty), PrototypePollutionBodyScan.urlEncodeWithoutPlus(validPropertyValue), insertionPointType);
            attackReq = Utilities.helpers.addParameter(baseReq, parameter);
            IParameter nullifyParameter = Utilities.helpers.buildParameter(PrototypePollutionBodyScan.urlEncodeWithoutPlus(invalidProperty), PrototypePollutionBodyScan.urlEncodeWithoutPlus(invalidPropertyValue), insertionPointType);
            byte[] nullifyReq = Utilities.helpers.addParameter(baseReq, nullifyParameter);
            doAttack(baseReq, service, attackReq, nullifyReq);
        }
    }

    void doAttack(byte[] baseReq, IHttpService service, byte[] attackReq, byte[] nullifyReq) {
        String validProperty = Utilities.globalSettings.getString("valid property name");
        String invalidProperty = Utilities.globalSettings.getString("invalid property name");
        String regex = Utilities.globalSettings.getString("vulnerable response regex");

        Resp attackResp = request(service, attackReq, PrototypePollutionBodyScan.MAX_RETRIES);
        if(PrototypePollutionJSPropertyParamScan.regexResponse(attackResp)) {
            Resp nullifyResp = request(service, nullifyReq, PrototypePollutionBodyScan.MAX_RETRIES);
            if(!PrototypePollutionJSPropertyParamScan.regexResponse(nullifyResp)) {
                IHttpRequestResponseWithMarkers attackRespWithMarkers = Utilities.callbacks.applyMarkers(attackResp.getReq(), PrototypePollutionJSPropertyParamScan.getMatches(attackResp.getReq().getRequest(), validProperty.getBytes()), PrototypePollutionJSPropertyParamScan.getRegexMarkerPositions(attackResp, regex));
                IHttpRequestResponseWithMarkers nullifyRespWithMarkers = Utilities.callbacks.applyMarkers(nullifyResp.getReq(), PrototypePollutionJSPropertyParamScan.getMatches(nullifyResp.getReq().getRequest(), invalidProperty.getBytes()),null);
                PrototypePollutionBodyScan.reportIssue("Add property scan using "+validProperty, "An added parameter "+validProperty+" was added to the request and a regex \""+regex+"\" was used to see if it causes a response difference.", "Low", "Firm", ".", baseReq, new Resp(attackRespWithMarkers), new Resp(nullifyRespWithMarkers));
            }
        }
    }
}
