package burp;

import java.util.List;

public class ConstructorScanAddParam extends Scan {

    private final Integer MAX_RETRIES = 3;

    ConstructorScanAddParam(String name) {
        super(name);
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
        IParameter parameter = Utilities.helpers.buildParameter(Utilities.helpers.urlEncode(ConstructorParamScan.validProperty), Utilities.helpers.urlEncode(ConstructorParamScan.validProperty), insertionPointType);
        byte[] attackReq = Utilities.helpers.addParameter(baseReq, parameter);
        Resp attackResp = request(service, attackReq, MAX_RETRIES);
        if(ConstructorParamScan.hasNativeCode(attackResp)) {
            IParameter nullifyParameter = Utilities.helpers.buildParameter(Utilities.helpers.urlEncode(ConstructorParamScan.invalidProperty), Utilities.helpers.urlEncode(ConstructorParamScan.invalidProperty), insertionPointType);
            byte[] nullifyReq = Utilities.helpers.addParameter(baseReq, nullifyParameter);
            Resp nullifyResp = request(service, nullifyReq, MAX_RETRIES);
            if(!ConstructorParamScan.hasNativeCode(nullifyResp)) {
                IHttpRequestResponseWithMarkers attackRespWithMarkers = Utilities.callbacks.applyMarkers(attackResp.getReq(), ConstructorParamScan.getMatches(attackResp.getReq().getRequest(), ConstructorParamScan.validProperty.getBytes()),ConstructorParamScan.getNativeCodeMarkerPositions(attackResp));
                IHttpRequestResponseWithMarkers nullifyRespWithMarkers = Utilities.callbacks.applyMarkers(nullifyResp.getReq(), ConstructorParamScan.getMatches(nullifyResp.getReq().getRequest(), ConstructorParamScan.invalidProperty.getBytes()),null);
                ServerSidePrototypePollutionScan.reportIssue("ConstructorScanAddParam leaking native code", "An added parameter constructor was added to the request and it indicates that this was being used to reference a JavaScript property.", "Low", "Firm", ".", baseReq, new Resp(attackRespWithMarkers), new Resp(nullifyRespWithMarkers));
            }
        }
    }
}
