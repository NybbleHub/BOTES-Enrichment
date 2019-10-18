package com.botes.enrich.redis;

import com.botes.enrich.onyphe.OnypheOps;
import com.botes.enrich.shodan.ShodanOps;
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



public class AsyncRedisIPEnrichment extends RichAsyncFunction<ObjectNode, String> {

    private transient RedisClient shodanRedisClient;
    private transient RedisClient onypheRedisClient;
    private transient RedisAsyncCommands<String, String> shodanRedisAsyncCommands;
    private transient RedisAsyncCommands<String, String> onypheRedisAsyncCommands;


    @Override
    public void open(Configuration parameters) throws Exception {
        super.open(parameters);
        shodanRedisClient = RedisClient.create("redis://localhost:6379/0");
        onypheRedisClient = RedisClient.create("redis://localhost:6379/1");
        shodanRedisAsyncCommands = shodanRedisClient.connect().async();
        onypheRedisAsyncCommands = onypheRedisClient.connect().async();
    }

    @Override
    public void close() throws Exception {
        super.close();
        shodanRedisClient.shutdown();
        onypheRedisClient.shutdown();
    }

    @Override
    public void asyncInvoke(ObjectNode jsonNodes, final ResultFuture<String> resultFuture) throws Exception {

        String redisKey = jsonNodes.get("value").get("destination.ip").asText();

            if (shodanRedisAsyncCommands.exists(redisKey).get() == 0) {
                ShodanOps shodanOps = new ShodanOps();
                String shodanResult = shodanOps.queryShodan(redisKey);
                shodanRedisAsyncCommands.set(redisKey, shodanResult);
            }
            if (onypheRedisAsyncCommands.exists(redisKey).get() == 0) {
                OnypheOps onypheOps = new OnypheOps();
                String onypheResult = onypheOps.queryOnyphe(redisKey);
                onypheRedisAsyncCommands.set(redisKey, onypheResult);
            }
            RedisFuture<String> shodanPull = shodanRedisAsyncCommands.get(redisKey);
            RedisFuture<String> onpyhePull = onypheRedisAsyncCommands.get(redisKey);

            CompletableFuture.supplyAsync(new Supplier<String>() {
                @Override
                public String get() {
                    try {
                        ObjectNode shodanResultNode = new ObjectMapper().readTree(shodanPull.get()).deepCopy();
                        ObjectNode onypheResultNode = new ObjectMapper().readTree(onpyhePull.get()).deepCopy();
                        ObjectNode jsonLogs = jsonNodes.get("value").deepCopy();
                        jsonLogs.setAll(shodanResultNode);
                        jsonLogs.setAll(onypheResultNode);
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