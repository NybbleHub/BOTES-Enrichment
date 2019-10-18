package com.botes.enrich.onyphe;

import org.apache.flink.shaded.jackson2.com.fasterxml.jackson.annotation.JsonInclude;
import org.apache.flink.shaded.jackson2.com.fasterxml.jackson.databind.JsonNode;
import org.apache.flink.shaded.jackson2.com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.flink.shaded.jackson2.com.fasterxml.jackson.databind.node.ArrayNode;
import org.apache.flink.shaded.jackson2.com.fasterxml.jackson.databind.node.ObjectNode;
import org.asynchttpclient.*;
import static org.asynchttpclient.Dsl.*;

import java.io.IOException;
import java.util.Iterator;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.TimeoutException;

public class OnypheOps {

    private String onypheAPIKey = "$API_KEY";
    private String onypheResult;
    private ObjectMapper mapper = new ObjectMapper();
    private ObjectNode onypheGetBody;
    private ObjectNode onypheResultNode = mapper.createObjectNode();

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public String queryOnyphe (String onypheQueryIP) throws IOException, ExecutionException, InterruptedException, TimeoutException {

        AsyncHttpClient onypheAsyncClient = asyncHttpClient();
        Future<Response> onypheGetRequest = onypheAsyncClient.prepareGet("https://www.onyphe.io/api/ip/" + onypheQueryIP + "?apikey=" + onypheAPIKey).execute();

        onypheGetBody = mapper.readValue(onypheGetRequest.get().getResponseBody(), ObjectNode.class);
        if (!onypheGetBody.has("results")) {
            return "{}";
        } else {
            if (!onypheGetBody.get("results").hasNonNull(1)) {
                return "{}";
            } else {
                onypheResult = processOnypheGetResult(onypheGetBody);
                return onypheResult;
            }

        }
    }


    public String processOnypheGetResult (ObjectNode onypheGetResultNode) {

        ArrayNode onypheResultArray = onypheGetResultNode.get("results").deepCopy();
        Iterator<JsonNode> onypheResultIterator = onypheResultArray.elements();

        while (onypheResultIterator.hasNext()) {
            ObjectNode onypheResultSingle = onypheResultIterator.next().deepCopy();

            if (onypheResultSingle.get("@category").asText().equals("datascan")) {
                onypheResultNode.set("onyphe.datascan.data", onypheResultSingle.get("data"));
                onypheResultNode.set("onyphe.datascan.port", onypheResultSingle.get("port"));
                onypheResultNode.set("onyphe.datascan.product", onypheResultSingle.get("product"));
                onypheResultNode.set("onyphe.datascan.productvendor", onypheResultSingle.get("productvendor"));
                onypheResultNode.set("onyphe.datascan.productversion", onypheResultSingle.get("productversion"));
                onypheResultNode.set("onyphe.datascan.protocol", onypheResultSingle.get("protocol"));
                onypheResultNode.set("onyphe.datascan.source", onypheResultSingle.get("source"));
                onypheResultNode.set("onyphe.datascan.tls", onypheResultSingle.get("tls"));
                onypheResultNode.set("onyphe.datascan.url", onypheResultSingle.get("url"));
            } else if (onypheResultSingle.get("@category").asText().equals("pastries")) {
                onypheResultNode.set("onyphe.pastries.domain", onypheResultSingle.get("domain"));
                onypheResultNode.set("onyphe.pastries.file", onypheResultSingle.get("file"));
                onypheResultNode.set("onyphe.pastries.ip", onypheResultSingle.get("ip"));
                onypheResultNode.set("onyphe.pastries.size", onypheResultSingle.get("size"));
                onypheResultNode.set("onyphe.pastries.source", onypheResultSingle.get("source"));
                onypheResultNode.set("onyphe.pastries.syntax", onypheResultSingle.get("syntax"));
                onypheResultNode.set("onyphe.pastries.url", onypheResultSingle.get("url"));
            } else if (onypheResultSingle.get("@category").asText().equals("resolver")) {
                onypheResultNode.set("onyphe.resolver.domain", onypheResultSingle.get("domain"));
                onypheResultNode.set("onyphe.resolver.forward", onypheResultSingle.get("forward"));
                onypheResultNode.set("onyphe.resolver.hostname", onypheResultSingle.get("hostname"));
                onypheResultNode.set("onyphe.resolver.organization", onypheResultSingle.get("organization"));
                onypheResultNode.set("onyphe.resolver.reverse", onypheResultSingle.get("reverse"));
                onypheResultNode.set("onyphe.resolver.source", onypheResultSingle.get("source"));
                onypheResultNode.set("onyphe.resolver.type", onypheResultSingle.get("type"));
            } else if (onypheResultSingle.get("@category").asText().equals("synscan")) {
                onypheResultNode.set("onyphe.synscan.os", onypheResultSingle.get("os"));
                onypheResultNode.set("onyphe.synscan.port", onypheResultSingle.get("port"));
                onypheResultNode.set("onyphe.synscan.source", onypheResultSingle.get("source"));
            } else if (onypheResultSingle.get("@category").asText().equals("threatlist")) {
                onypheResultNode.set("onyphe.threatlist.domain", onypheResultSingle.get("domain"));
                onypheResultNode.set("onyphe.threatlist.organization", onypheResultSingle.get("organization"));
                onypheResultNode.set("onyphe.threatlist.source", onypheResultSingle.get("source"));
                onypheResultNode.set("onyphe.threatlist.tag", onypheResultSingle.get("tag"));
                onypheResultNode.set("onyphe.threatlist.listname", onypheResultSingle.get("threatlist"));
            }
        }
        return onypheResultNode.toString();
    }
}

