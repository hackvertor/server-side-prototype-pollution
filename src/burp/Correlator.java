package burp;

import java.util.HashMap;

class Correlator {

    private IBurpCollaboratorClientContext collab;
    private HashMap<Integer, MetaRequest> requests;
    private int count = 0;
    private HashMap<String, Integer> idToRequestID = new HashMap<>();
    private int maxRequestStorageLimit = 100000;

    Correlator() {
        requests = new LimitedHashMap<>(maxRequestStorageLimit);
        collab = Utilities.callbacks.createBurpCollaboratorClientContext();
    }

    java.util.List<IBurpCollaboratorInteraction> poll() {
        return collab.fetchAllCollaboratorInteractions();
    }

    Integer addRequest(MetaRequest req) {
        int requestCode = count++;
        requests.put(requestCode, req);
        return requestCode;
    }

    void addCollboratorPayload(String id, int requestId) {
        idToRequestID.put(id, requestId);
    }

    String generateCollabId() {
        return collab.generatePayload(false);
    }

    String getCollabLocation() {
        return collab.getCollaboratorServerLocation();
    }

    MetaRequest getRequest(String collabId) {
        if(idToRequestID.containsKey(collabId)) {
            int requestId = idToRequestID.get(collabId);
            return requests.get(requestId);
        } else {
            return null;
        }
    }
}