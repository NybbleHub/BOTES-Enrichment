package com.botes.enrich.redis;

import com.botes.enrich.virustotal.VirusTotalOps;
import io.lettuce.core.RedisClient;
import io.lettuce.core.RedisFuture;
import io.lettuce.core.api.async.RedisAsyncCommands;
import org.apache.flink.configuration.Configuration;
import org.apache.flink.shaded.jackson2.com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.flink.shaded.jackson2.com.fasterxml.jackson.databind.node.ObjectNode;
import org.apache.flink.streaming.api.functions.async.ResultFuture;
import org.apache.flink.streaming.api.functions.async.RichAsyncFunction;

import java.io.IOException;
import java.util.Collections;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.function.Supplier;


public class AsyncRedisFileEnrichment extends RichAsyncFunction<ObjectNode, String> {

    private transient RedisClient virusTotalRedisClient;
    private transient RedisAsyncCommands<String, String> virusTotalRedisAsyncCommands;
    private String redisKey;

    @Override
    public void open(Configuration parameters) throws Exception {
        super.open(parameters);
        virusTotalRedisClient = RedisClient.create("redis://localhost:6379/2");
        virusTotalRedisAsyncCommands = virusTotalRedisClient.connect().async();
    }

    @Override
    public void close() throws Exception {
        super.close();
        virusTotalRedisClient.shutdown();
    }

    @Override
    public void asyncInvoke(ObjectNode jsonNodes, final ResultFuture<String> resultFuture) throws Exception {

        if (jsonNodes.get("value").has("file.hash.sha256")) {
            redisKey = jsonNodes.get("value").get("file.hash.sha256").asText();
        } else if (jsonNodes.get("value").has("file.hash.sha1")) {
            redisKey = jsonNodes.get("value").get("file.hash.sha1").asText();
        } else if (jsonNodes.get("value").has("file.hash.md5")) {
            redisKey = jsonNodes.get("value").get("file.hash.md5").asText();
        }

            if (virusTotalRedisAsyncCommands.exists(redisKey).get() == 0) {
                VirusTotalOps virusTotalOps = new VirusTotalOps();
                String virusTotalResult = virusTotalOps.queryVirusTotal(redisKey);
                System.out.println("Set to Redis : " + virusTotalResult);
                virusTotalRedisAsyncCommands.set(redisKey, virusTotalResult);
            }
            RedisFuture<String> virusTotalPull = virusTotalRedisAsyncCommands.get(redisKey);


            CompletableFuture.supplyAsync(new Supplier<String>() {
                @Override
                public String get() {
                    try {
                        ObjectNode virusTotalResultNode = new ObjectMapper().readTree(virusTotalPull.get()).deepCopy();
                        ObjectNode jsonLogs = jsonNodes.get("value").deepCopy();
                        jsonLogs.setAll(virusTotalResultNode);
                        return jsonLogs.toString();
                    } catch (InterruptedException | ExecutionException | IOException e) {
                        return null;
                    }
                }
            }).thenAccept( (String dbResult) -> {
                resultFuture.complete(Collections.singleton(dbResult));
            });
    }
}