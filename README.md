# BOTES Security Dataset real-time enrichement

This simple demo show how to use real-time data streaming and processing platform in order to achieve enrichment of IPs and Files information at high velocity and though asynchronous API calls to external sources.

Enrichment infrastructure components are:

* Logstash: to parse and normalize events in ECS format.
* Apache Kafka: to handle events as pub/sub messaging system.
* Apache Flink: to process events as real-time data streaming and processing platform. 
* Redis: to store result from external sources and limit number of API call.
* Elasticsearch: to index enriched events.

External sources for enrichment are:

* Onyhpe: for IP enrichment.
* Shodan: for IP enrichment.
* VirusTotal: for File hash enrichment.

# Documentation

BOTES Dataset enrichment process is fully documented here: [BOTES Enrichement GitBook documentation](https://botes.gitbook.io/botes-dataset/botes-enrichement/)

Documentation provides details about installation and configuration of each components of the demo, information about the dataflow and the code itself.
