package burp;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ConstructorParamScan extends ParamScan {

    private final Integer MAX_RETRIES = 3;

    public ConstructorParamScan(String name) {
        super(name);
    }

    @Override
    List<IScanIssue> doScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        IHttpService service = baseRequestResponse.getHttpService();

        byte[] attackReq = insertionPoint.buildRequest(("constructor").getBytes());
        Resp attackResp = request(service, attackReq, MAX_RETRIES);

        if(hasNativeCode(attackResp)) {
            byte[] nullifyReq = insertionPoint.buildRequest(("constxructor").getBytes());
            Resp nullifyResp = request(service, nullifyReq, MAX_RETRIES);
            if(!hasNativeCode(nullifyResp)) {
                ServerSidePrototypePollutionScan.reportIssue("ConstructorParamScan leaking native code", "The parameter "+insertionPoint.getInsertionPointName()+" was identified that seems to indicate that it is being reference in a JavaScript property using the constructor property name.", "Low", "Firm", ".", baseRequestResponse.getRequest(), attackResp, nullifyResp);
            }
        }

        return null;
    }

    static Boolean hasNativeCode(Resp response) {
        String responseStr = Utilities.helpers.bytesToString(response.getReq().getResponse());
        Pattern p = Pattern.compile("native.{1,10}code");
        Matcher m = p.matcher(responseStr);
        return m.find();
    }
}
