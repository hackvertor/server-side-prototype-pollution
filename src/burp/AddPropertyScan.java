package burp;

import java.util.List;

public class AddPropertyScan extends Scan {

    private final Integer MAX_RETRIES = 3;

    AddPropertyScan(String name) {
        super(name);
        scanSettings.register("vulnerable response regex", PropertyParamScan.DEFAULT_RESPONSE_REGEX, "Regex used to see if the server behaves differently");
        scanSettings.register("valid property name", PropertyParamScan.DEFAULT_VALID_PROPERTY, "Valid property name that causes behaviour difference");
        scanSettings.register("invalid property name", PropertyParamScan.DEFAULT_INVALID_PROPERTY, "Invalid property name that doesn't trigger different behaviour");
    }

    @Override
    List<IScanIssue> doScan(byte[] baseReq, IHttpService service) {
        doAttack(baseReq, service, IScannerInsertionPoint.INS_PARAM_COOKIE);
        doAttack(baseReq, service, IScannerInsertionPoint.INS_PARAM_BODY);
        doAttack(baseReq, service, IScannerInsertionPoint.INS_PARAM_URL);
        doAttack(baseReq, service, IScannerInsertionPoint.INS_PARAM_JSON);

        return null;
    }

    public void doAttack(byte[] baseReq, IHttpService service, byte insertionPointType) {

        String validProperty = Utilities.globalSettings.getString("valid property name");
        String invalidProperty = Utilities.globalSettings.getString("invalid property name");
        String regex = Utilities.globalSettings.getString("vulnerable response regex");

        IParameter parameter = Utilities.helpers.buildParameter(PrototypePollutionBodyScan.urlEncodeWithoutPlus(validProperty), PrototypePollutionBodyScan.urlEncodeWithoutPlus(validProperty), insertionPointType);
        byte[] attackReq = Utilities.helpers.addParameter(baseReq, parameter);
        Resp attackResp = request(service, attackReq, MAX_RETRIES);
        if(PropertyParamScan.regexResponse(attackResp)) {
            IParameter nullifyParameter = Utilities.helpers.buildParameter(PrototypePollutionBodyScan.urlEncodeWithoutPlus(invalidProperty), PrototypePollutionBodyScan.urlEncodeWithoutPlus(invalidProperty), insertionPointType);
            byte[] nullifyReq = Utilities.helpers.addParameter(baseReq, nullifyParameter);
            Resp nullifyResp = request(service, nullifyReq, MAX_RETRIES);
            if(!PropertyParamScan.regexResponse(nullifyResp)) {
                IHttpRequestResponseWithMarkers attackRespWithMarkers = Utilities.callbacks.applyMarkers(attackResp.getReq(), PropertyParamScan.getMatches(attackResp.getReq().getRequest(), validProperty.getBytes()), PropertyParamScan.getRegexMarkerPositions(attackResp, regex));
                IHttpRequestResponseWithMarkers nullifyRespWithMarkers = Utilities.callbacks.applyMarkers(nullifyResp.getReq(), PropertyParamScan.getMatches(nullifyResp.getReq().getRequest(), invalidProperty.getBytes()),null);
                PrototypePollutionBodyScan.reportIssue("Add property scan using "+validProperty, "An added parameter "+validProperty+" was added to the request and a regex \""+regex+"\" was used to see if it causes a response difference.", "Low", "Firm", ".", baseReq, new Resp(attackRespWithMarkers), new Resp(nullifyRespWithMarkers));
            }
        }
    }
}
