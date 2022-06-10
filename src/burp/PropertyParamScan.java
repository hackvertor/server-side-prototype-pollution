package burp;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class PropertyParamScan extends ParamScan {

    static final String DEFAULT_RESPONSE_REGEX = "native.{1,10}code";
    static public final String DEFAULT_VALID_PROPERTY = "constructor";
    static public final String DEFAULT_INVALID_PROPERTY = "constxructor";

    private final Integer MAX_RETRIES = 3;

    public PropertyParamScan(String name) {
        super(name);
        scanSettings.register("vulnerable response regex", PropertyParamScan.DEFAULT_RESPONSE_REGEX, "Regex used to see if the server behaves differently");
        scanSettings.register("valid property name", PropertyParamScan.DEFAULT_VALID_PROPERTY, "Valid property name that causes behaviour difference");
        scanSettings.register("invalid property name", PropertyParamScan.DEFAULT_INVALID_PROPERTY, "Invalid property name that doesn't trigger different behaviour");
    }

    @Override
    List<IScanIssue> doScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        IHttpService service = baseRequestResponse.getHttpService();

        String validProperty = Utilities.globalSettings.getString("valid property name");
        String invalidProperty = Utilities.globalSettings.getString("invalid property name");
        String regex = Utilities.globalSettings.getString("vulnerable response regex");


        byte[] attackReq = insertionPoint.buildRequest(PrototypePollutionScan.urlEncodeWithoutPlus(validProperty).getBytes());
        Resp attackResp = request(service, attackReq, MAX_RETRIES);
        if(regexResponse(attackResp)) {
            byte[] nullifyReq = insertionPoint.buildRequest(PrototypePollutionScan.urlEncodeWithoutPlus(invalidProperty).getBytes());
            Resp nullifyResp = request(service, nullifyReq, MAX_RETRIES);
            if(!regexResponse(nullifyResp)) {
                IHttpRequestResponseWithMarkers attackRespWithMarkers = Utilities.callbacks.applyMarkers(attackResp.getReq(), getMatches(attackResp.getReq().getRequest(), validProperty.getBytes()), getRegexMarkerPositions(attackResp, regex));
                IHttpRequestResponseWithMarkers nullifyRespWithMarkers = Utilities.callbacks.applyMarkers(nullifyResp.getReq(), getMatches(nullifyResp.getReq().getRequest(), invalidProperty.getBytes()),null);
                PrototypePollutionScan.reportIssue("Property param scan using "+validProperty, "The parameter "+insertionPoint.getInsertionPointName()+" was identified and a regex \""+regex+"\" was used to see if it causes a response difference.", "Low", "Firm", ".", baseRequestResponse.getRequest(), new Resp(attackRespWithMarkers), new Resp(nullifyRespWithMarkers));
            }
        }

        return null;
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
