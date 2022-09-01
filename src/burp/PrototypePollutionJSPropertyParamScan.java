package burp;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class PrototypePollutionJSPropertyParamScan extends ParamScan {

    static final String DEFAULT_RESPONSE_REGEX = PrototypePollutionBodyScan.BLITZ_REGEX;
    static public final String DEFAULT_VALID_PROPERTY = "__proto__.__proto__";
    static public final String DEFAULT_VALID_PROPERTY_VALUE = "{}";
    static public final String DEFAULT_INVALID_PROPERTY = "__proto__.y";
    static public final String DEFAULT_INVALID_PROPERTY_VALUE = "123";

    public PrototypePollutionJSPropertyParamScan(String name) {
        super(name);
        scanSettings.register("vulnerable response regex", DEFAULT_RESPONSE_REGEX, "Regex used to see if the server behaves differently");
        scanSettings.register("valid property name", DEFAULT_VALID_PROPERTY, "Valid property name that causes behaviour difference");
        scanSettings.register("valid property value", DEFAULT_VALID_PROPERTY_VALUE, "Valid property value that causes behaviour difference");
        scanSettings.register("invalid property name", DEFAULT_INVALID_PROPERTY, "Invalid property name that doesn't trigger different behaviour");
        scanSettings.register("invalid property value", DEFAULT_INVALID_PROPERTY_VALUE, "Invalid property value that doesn't trigger different behaviour");
    }

    @Override
    List<IScanIssue> doScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        Utilities.out("--Running JS property param scan--");
        String validProperty = Utilities.globalSettings.getString("valid property name");
        String invalidProperty = Utilities.globalSettings.getString("invalid property name");
        byte[] attackReq = insertionPoint.buildRequest(PrototypePollutionBodyScan.urlEncodeWithoutPlus(validProperty).getBytes());
        byte[] nullifyReq = insertionPoint.buildRequest(PrototypePollutionBodyScan.urlEncodeWithoutPlus(invalidProperty).getBytes());
        if(attackReq != null && nullifyReq != null) {
            doAttack(baseRequestResponse, insertionPoint, attackReq, nullifyReq);
        }
        return null;
    }

    void doAttack(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint, byte[] attackReq, byte[] nullifyReq) {
        IHttpService service = baseRequestResponse.getHttpService();
        String validProperty = Utilities.globalSettings.getString("valid property name");
        String invalidProperty = Utilities.globalSettings.getString("invalid property name");
        String regex = Utilities.globalSettings.getString("vulnerable response regex");

        Resp attackResp = request(service, attackReq, PrototypePollutionBodyScan.MAX_RETRIES);
        if(attackResp.getReq().getResponse() != null && regexResponse(attackResp)) {
            Resp nullifyResp = request(service, nullifyReq, PrototypePollutionBodyScan.MAX_RETRIES);
            if(nullifyResp.getReq().getResponse() != null && !regexResponse(nullifyResp)) {
                IHttpRequestResponseWithMarkers attackRespWithMarkers = Utilities.callbacks.applyMarkers(attackResp.getReq(), getMatches(attackResp.getReq().getRequest(), validProperty.getBytes()), getRegexMarkerPositions(attackResp, regex));
                IHttpRequestResponseWithMarkers nullifyRespWithMarkers = Utilities.callbacks.applyMarkers(nullifyResp.getReq(), getMatches(nullifyResp.getReq().getRequest(), invalidProperty.getBytes()),null);
                PrototypePollutionBodyScan.reportIssue("Property param scan using "+validProperty, "The parameter "+insertionPoint.getInsertionPointName()+" was identified and a regex \""+regex+"\" was used to see if it causes a response difference.", "Low", "Firm", ".", baseRequestResponse.getRequest(), new Resp(attackRespWithMarkers), new Resp(nullifyRespWithMarkers));
            }
        }

    }

    static List<int[]> getRegexMarkerPositions(Resp response, String regex) {
        String responseStr = Utilities.helpers.bytesToString(response.getReq().getResponse());
        Pattern p = Pattern.compile(regex);
        Matcher m = p.matcher(responseStr);
        List<int[]> matches = new ArrayList<int[]>();
        while (m.find()) {
            matches.add(new int[] { m.start(), m.end() });
        }
        return matches;
    }

    static Boolean regexResponse(Resp response) {
        String responseStr = Utilities.helpers.bytesToString(response.getReq().getResponse());
        Pattern p = Pattern.compile(Utilities.globalSettings.getString("vulnerable response regex"));
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
