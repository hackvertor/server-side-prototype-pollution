package burp;
import java.util.List;

public class PrototypePollutionFullScan extends Scan {

    PrototypePollutionFullScan(String name) {
        super(name);
        for (Scan scan: BulkScan.scans) {
            scanSettings.importSettings(scan.scanSettings);
        }
    }

    @Override
    List<IScanIssue> doScan(byte[] baseReq, IHttpService service) {
       for (Scan scan: BulkScan.scans) {
           scan.doScan(baseReq, service);
       }
       return null;
    }
}
