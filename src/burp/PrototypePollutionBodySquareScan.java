package burp;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class PrototypePollutionBodySquareScan extends PrototypePollutionBodyScan {
    static final Map<String, String[]> jsonTechniquesSquare = new HashMap<String, String[]>()
    {
        {
            //__proto__
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
            put("blitz1", new String[]{
                    "__proto__[__proto__]","{}","\"xyz\""
            });
            put("blitz2", new String[]{
                    "","null","\"xyz\""
            });
            //constructor
//            put("spacing constructor", new String[]{
//                    "constructor[prototype][json spaces]","\" \"","\"\""
//            });
//            put("options constructor", new String[]{
//                    "constructor[prototype][head]","true","false"
//            });
//            put("status constructor", new String[]{
//                    "constructor[prototype][status]","510","0"
//            });
//            put("exposedHeaders constructor", new String[]{
//                    "constructor[prototype][exposedHeaders]","[\""+CANARY+"\"]","null"
//            });
//            put("blitz1 constructor", new String[]{
//                    "constructor[prototype][__proto__]","{}","\"xyz\""
//            });
        }
    };
    PrototypePollutionBodySquareScan(String name) {
        super(name);
    }

    public List<IScanIssue> doScan(byte[] baseReq, IHttpService service) {
        Utilities.out("--Running Body square scan--");
        for (Map.Entry<String, String[]> technique : jsonTechniquesSquare.entrySet()) {
            doAttack(baseReq, Utilities.getBody(baseReq), service, technique.getValue(), technique.getKey());
        }

        return null;
    }
}
