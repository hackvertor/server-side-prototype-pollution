package burp;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class PrototypePollutionBodySquareScan extends PrototypePollutionBodyScan {
    static final Map<String, String[]> jsonTechniquesSquare = new HashMap<String, String[]>()
    {
        {
            put("spacing", new String[]{
                    "__proto__[json spaces]","\" \"","\"\""
            });
            put("options", new String[]{
                    "__proto__[head]","true","false"
            });
            put("status", new String[]{
                    "__proto__[status]","510","0"
            });
            put("exposedHeaders", new String[]{
                    "__proto__[exposedHeaders]","[\""+CANARY+"\"]","null"
            });
        }
    };
    PrototypePollutionBodySquareScan(String name) {
        super(name);
    }

    public List<IScanIssue> doScan(byte[] baseReq, IHttpService service) {
        for (Map.Entry<String, String[]> technique : jsonTechniquesSquare.entrySet()) {
            doAttack(baseReq, Utilities.getBody(baseReq), service, technique.getValue(), technique.getKey());
        }

        return null;
    }
}