package burp;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ConstructorParamScan extends ParamScan {

    static final String nativeCodeRegex = "native.{1,10}code";
    static public final String validProperty = "constructor";
    static public final String invalidProperty = "constxructor";

    private final Integer MAX_RETRIES = 3;

    public ConstructorParamScan(String name) {
        super(name);
    }

    @Override
    List<IScanIssue> doScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        IHttpService service = baseRequestResponse.getHttpService();

        byte[] attackReq = insertionPoint.buildRequest((validProperty).getBytes());
        Resp attackResp = request(service, attackReq, MAX_RETRIES);
        if(hasNativeCode(attackResp)) {
            byte[] nullifyReq = insertionPoint.buildRequest((invalidProperty).getBytes());
            Resp nullifyResp = request(service, nullifyReq, MAX_RETRIES);
            if(!hasNativeCode(nullifyResp)) {
                IHttpRequestResponseWithMarkers attackRespWithMarkers = Utilities.callbacks.applyMarkers(attackResp.getReq(), getMatches(attackResp.getReq().getRequest(), validProperty.getBytes()),getNativeCodeMarkerPositions(attackResp));
                IHttpRequestResponseWithMarkers nullifyRespWithMarkers = Utilities.callbacks.applyMarkers(nullifyResp.getReq(), getMatches(nullifyResp.getReq().getRequest(), invalidProperty.getBytes()),null);
                ServerSidePrototypePollutionScan.reportIssue("ConstructorParamScan leaking native code", "The parameter "+insertionPoint.getInsertionPointName()+" was identified that seems to indicate that it is being reference in a JavaScript property using the constructor property name.", "Low", "Firm", ".", baseRequestResponse.getRequest(), new Resp(attackRespWithMarkers), new Resp(nullifyRespWithMarkers));
            }
        }

        return null;
    }

    static List<int[]> getNativeCodeMarkerPositions(Resp response) {
        String responseStr = Utilities.helpers.bytesToString(response.getReq().getResponse());
        Pattern p = Pattern.compile(nativeCodeRegex);
        Matcher m = p.matcher(responseStr);
        List<int[]> matches = new ArrayList<int[]>();
        while (m.find()) {
            matches.add(new int[] { m.start(), m.end() });
        }
        return matches;
    }

    static Boolean hasNativeCode(Resp response) {
        String responseStr = Utilities.helpers.bytesToString(response.getReq().getResponse());
        Pattern p = Pattern.compile(nativeCodeRegex);
        Matcher m = p.matcher(responseStr);
        return m.find();
    }

    static List<int[]> getMatches(byte[] response, byte[] match)
    {
        List<int[]> matches = new ArrayList<int[]>();

        int start = 0;
        while (start < response.length)
        {
            start = Utilities.helpers.indexOf(response, match, true, start, response.length);
            if (start == -1)
                break;
            matches.add(new int[] { start, start + match.length });
            start += match.length;
        }

        return matches;
    }
}
