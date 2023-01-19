package burp;

import java.net.MalformedURLException;
import java.net.URL;
import java.text.SimpleDateFormat;
import java.util.Date;

class Monitor implements Runnable, IExtensionStateListener {
    private Correlator collab;
    private boolean stop = false;

    Monitor(Correlator collab) {
        this.collab = collab;
    }

    public void extensionUnloaded() {
        Utilities.out("Extension unloading - triggering abort");
        stop = true;
        Thread.currentThread().interrupt();
    }

    public void run() {
        try {
            while (!stop) {
                Thread.sleep(10000);
                collab.poll().forEach(e -> processInteraction(e));
            }
        }
        catch (InterruptedException e) {
            Utilities.out("Interrupted");
        }
        catch (Exception e) {
            Utilities.out("Error fetching/handling interactions: "+e.getMessage());
        }

        Utilities.out("Shutting down collaborator monitor thread");
    }

    private void processInteraction(IBurpCollaboratorInteraction interaction) {
        String id = interaction.getProperty("interaction_id");
        Utilities.out("Got an interaction:"+interaction.getProperties());
        MetaRequest metaReq = collab.getRequest(id);
        IHttpRequestResponse req = null;
        if(metaReq != null) {
            req = metaReq.getRequest();
        }
        String severity = "High";
        String ipAddress = interaction.getProperty("client_ip");

        String rawDetail = interaction.getProperty("request");
        if (rawDetail == null) {
            rawDetail = interaction.getProperty("conversation");
        }

        if (rawDetail == null) {
            rawDetail = interaction.getProperty("raw_query");
        }
        String message = "Server side prototype pollution was found asynchronously. See the request and response to view the technique used.<br/><br/>";
        message += "The collaborator was contacted by <b>" + ipAddress;
        message +=  "</b>";

        if(metaReq != null) {
            try {
                long interactionTime = new SimpleDateFormat("yyyy-MMM-dd HH:mm:ss.SSS z").parse(interaction.getProperty("time_stamp")).getTime();
                long mill = interactionTime - metaReq.getTimestamp();
                int seconds = (int) (mill / 1000) % 60;
                int minutes = (int) ((mill / (1000 * 60)) % 60);
                int hours = (int) ((mill / (1000 * 60 * 60)) % 24);
                message += " after a delay of <b>" + String.format("%02d:%02d:%02d", hours, minutes, seconds) + "</b>:<br/><br/>";
            } catch (java.text.ParseException e) {
                message += e.toString();
            }
        }

        String decodedDetail = new String(Utilities.helpers.base64Decode(rawDetail));
        message += "<pre>    "+decodedDetail.replace("<", "&lt;").replace("\n", "\n    ")+"</pre>";

        if(metaReq != null) {
            message += "The payload was sent at " + new Date(metaReq.getTimestamp()) + " and received on " + interaction.getProperty("time_stamp") + "<br/><br/>";
        }

        message += "To manually replicate this issue, use the Burp Collaborator Client available in the main tabs.<br/><br/>";
        IRequestInfo reqInfo = null;
        if(req != null) {
            reqInfo = Utilities.callbacks.getHelpers().analyzeRequest(req.getHttpService(), req.getRequest());
        }
        if(req != null) {
            Utilities.callbacks.addScanIssue(
                new CustomScanIssue(req.getHttpService(), reqInfo.getUrl(), new IHttpRequestResponse[]{req}, "Server Side Prototype Pollution Collaborator pingback (" + interaction.getProperty("type") + "): ", message + interaction.getProperties().toString(), severity, "Certain", PrototypePollutionBodyScan.REMEDIATION)
            );
        } else {
            URL url = null;
            try {
                url = new URL("http://unknown");
            } catch (MalformedURLException e) {

            }
            Utilities.callbacks.addScanIssue(
                new CustomScanIssue(Utilities.helpers.buildHttpService("unknown", 80, false), url, new IHttpRequestResponse[]{}, "Server Side Prototype Pollution Collaborator pingback (" + interaction.getProperty("type") + "): ", message + interaction.getProperties().toString(), severity, "Certain", "Panic")
            );
        }
    }

}