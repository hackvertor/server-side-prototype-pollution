package burp;

import java.util.List;

public class PrototypePollutionParamDotScan extends PrototypePollutionParamScan{
    PrototypePollutionParamDotScan(String name) {
        super(name);
    }

    @Override
    List<IScanIssue> doScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {

        Utilities.out("--Running param dot scan--");

        switch(insertionPoint.getInsertionPointType()) {
            case IScannerInsertionPoint.INS_PARAM_BODY:
            case IScannerInsertionPoint.INS_PARAM_URL:
            case IScannerInsertionPoint.INS_PARAM_COOKIE:
            case IScannerInsertionPoint.INS_PARAM_JSON:
                injectInsertionPoint(baseRequestResponse, insertionPoint, PrototypePollutionBodyDotScan.jsonTechniques);
                break;
        }
        return null;
    }
}
