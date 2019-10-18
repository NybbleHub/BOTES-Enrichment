package com.botes.enrich;

import com.botes.enrich.redis.AsyncRedisFileEnrichment;
import com.botes.enrich.redis.AsyncRedisIPEnrichment;
import org.apache.flink.api.common.functions.FilterFunction;
import org.apache.flink.api.common.functions.RuntimeContext;
import org.apache.flink.shaded.jackson2.com.fasterxml.jackson.databind.node.ObjectNode;
import org.apache.flink.streaming.api.datastream.AsyncDataStream;
import org.apache.flink.streaming.api.datastream.DataStream;
import org.apache.flink.streaming.api.environment.StreamExecutionEnvironment;
import org.apache.flink.streaming.connectors.kafka.FlinkKafkaConsumer;
import org.apache.flink.streaming.util.serialization.JSONKeyValueDeserializationSchema;
import org.apache.flink.streaming.connectors.elasticsearch.ElasticsearchSinkFunction;
import org.apache.flink.streaming.connectors.elasticsearch.RequestIndexer;
import org.apache.flink.streaming.connectors.elasticsearch6.ElasticsearchSink;
import org.apache.http.HttpHost;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.client.Requests;

import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class BotesEnrich {

	public static void main(String[] args) throws Exception {

		// Regex that match Private IPv4 and Google DNS
		String publicIPRegex = "(^0\\.)|(^10\\.)|(^127\\.)|(^169\\.254\\.)|(^192\\.168\\.)|(^172\\.1[6-9]\\.)|(^172\\.2[0-9]\\.)|(^172\\.3[0-1]\\.)|(^22[4-9]\\.)|(^23[0-9]\\.)(^24[0-9]\\.)(^25[0-5]\\.)|(8.8.8.8)|(8.8.4.4)";
		Pattern publicIPPattern = Pattern.compile(publicIPRegex);

		// Set up the streaming execution environment
		final StreamExecutionEnvironment env = StreamExecutionEnvironment.getExecutionEnvironment();

		// Set up Kafka environment
		Properties kafkaProperties = new Properties();
		kafkaProperties.setProperty("bootstrap.servers", "127.0.0.1:9092");
		kafkaProperties.setProperty("group.id", "flink_kafka_consumer");

		// Set up ElasticSearch environment
		List<HttpHost> httpHosts = new ArrayList<>();
		httpHosts.add(new HttpHost("127.0.0.1", 9200, "http"));

		// Create a Kafka consumer where topic is "firewall-logs", using JSON Deserialization schema and properties provided above. Read from the beginning.
		JSONKeyValueDeserializationSchema logsSchema = new JSONKeyValueDeserializationSchema(false);
		FlinkKafkaConsumer<ObjectNode> logsConsumer = new FlinkKafkaConsumer("firewall-logs", logsSchema, kafkaProperties);
		logsConsumer.setStartFromEarliest();

		// Create a ElasticSearch sink where index is "botes"
		ElasticsearchSink.Builder<String> esSinkBuilder = new ElasticsearchSink.Builder<>(httpHosts, new ElasticsearchSinkFunction<String>() {
			public IndexRequest createIndexRequest(String element) {
				Map<String, String> json = new HashMap<>();
				json.put("data", element);

				return Requests.indexRequest()
						.index("botes")
						.type("firewall")
						.source(json);
			}

			@Override
			public void process(String element, RuntimeContext ctx, RequestIndexer indexer) {
				indexer.add(createIndexRequest(element));
			}
		});

		// Configuration for the bulk requests; this instructs the sink to emit after every element, otherwise they would be buffered
		esSinkBuilder.setBulkFlushMaxActions(1);

		// Create stream where "destination.ip" field exists and contains only Public IPv4, except Google DNS.
		DataStream<ObjectNode> logsStreamIP = env.addSource(logsConsumer).filter(new FilterFunction<ObjectNode>() {
			@Override
			public boolean filter(ObjectNode jsonNodes) throws Exception {
				return jsonNodes.get("value").get("destination.ip") != null;
			}
		}).filter(new FilterFunction<ObjectNode>() {
			@Override
			public boolean filter(ObjectNode jsonNodes) throws Exception {
				Matcher publicIPMatcher = publicIPPattern.matcher(jsonNodes.get("value").get("destination.ip").toString());
				return !publicIPMatcher.find();
			}
		});

		// Create stream where "file.hash.*" field(s) exists.
		DataStream<ObjectNode> logsStreamFile = env.addSource(logsConsumer).filter(new FilterFunction<ObjectNode>() {
			@Override
			public boolean filter(ObjectNode jsonNodes) throws Exception {
				return (jsonNodes.get("value").get("file.hash.sha256") != null || jsonNodes.get("value").get("file.hash.sha1") != null || jsonNodes.get("value").get("file.hash.md5") != null);
			}
		});

		// Create AsyncDataStream with Async Function to enrich logs containing file hash, from VirusTotal API.
		DataStream<String> enrichmentStreamFile = AsyncDataStream.unorderedWait(logsStreamFile, new AsyncRedisFileEnrichment(), 5000, TimeUnit.MILLISECONDS).setParallelism(4);

		// Create AsyncDataStream with Async Function to enrcih logs containing destination IP, from Shodan and Onpyhe API.
		DataStream<String> enrichmentStreamIP = AsyncDataStream.unorderedWait(logsStreamIP, new AsyncRedisIPEnrichment(), 5000, TimeUnit.MILLISECONDS).setParallelism(4);

		//Print DataStream
		enrichmentStreamFile.print();
		enrichmentStreamIP.print();

		// Send DataStream to ElasticSearch
		enrichmentStreamFile.addSink(esSinkBuilder.build());
		enrichmentStreamIP.addSink(esSinkBuilder.build());

		env.execute("BOTES enrichement stream");
	}
}
