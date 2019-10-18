package com.botes.enrich.virustotal;

import org.apache.flink.shaded.jackson2.com.fasterxml.jackson.databind.JsonNode;
import org.apache.flink.shaded.jackson2.com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.flink.shaded.jackson2.com.fasterxml.jackson.databind.node.ArrayNode;
import org.apache.flink.shaded.jackson2.com.fasterxml.jackson.databind.node.ObjectNode;
import org.asynchttpclient.AsyncHttpClient;
import org.asynchttpclient.Response;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;

import static org.asynchttpclient.Dsl.asyncHttpClient;

public class VirusTotalOps {

    private String virusTotalAPIKey = "$API_KEY";
    private String virusTotalResult;
    private ObjectMapper mapper = new ObjectMapper();
    private JsonNode virusTotalResultNodeRoot;
    private ObjectNode virusTotalResultNode;
    private ObjectNode virusTotalGetBody = mapper.createObjectNode();
    private ObjectNode virusTotalProcessResult = mapper.createObjectNode();
    private ArrayNode virusTotalDataArray = mapper.createArrayNode();
    private List<String> virusTotalDataList = new ArrayList<String>();

    public String queryVirusTotal(String virusTotalFilehash) throws IOException, ExecutionException, InterruptedException {

        AsyncHttpClient virusTotalAsyncClient = asyncHttpClient();
        Future<Response> virusTotalGetRequest = virusTotalAsyncClient.prepareGet("https://www.virustotal.com/vtapi/v2/file/report?apikey=" + virusTotalAPIKey + "&resource=" + virusTotalFilehash).execute();

        virusTotalGetBody = mapper.readValue(virusTotalGetRequest.get().getResponseBody(), ObjectNode.class);
        virusTotalResult = processVirusTotalGetResult(virusTotalGetBody);
        return virusTotalResult;
    }


    public String processVirusTotalGetResult(ObjectNode virusTotalGetResultNode) throws IOException {

        virusTotalResultNode = virusTotalGetResultNode.path("scans").deepCopy();

        Iterator<Map.Entry<String, JsonNode>> virusTotalFieldIterator = virusTotalResultNode.fields();

        while (virusTotalFieldIterator.hasNext()) {
            Map.Entry<String, JsonNode> virusTotalField = virusTotalFieldIterator.next();

            if (virusTotalField.getValue().get("detected").toString().equals("true")) {
                ObjectNode virusTotalValue = virusTotalField.getValue().deepCopy();
                virusTotalValue.put("source", virusTotalField.getKey());
                virusTotalDataList.add(virusTotalValue.toString());
                virusTotalDataArray.add(mapper.valueToTree(virusTotalDataList));
            }
        }
        virusTotalProcessResult.set("virustotal.result", virusTotalDataArray);
        return virusTotalProcessResult.toString();
    }
}
