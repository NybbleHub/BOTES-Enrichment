package com.botes.enrich.shodan;

import com.fooock.shodan.*;
import com.fooock.shodan.model.host.Host;
import io.lettuce.core.api.async.RedisAsyncCommands;
import io.reactivex.observers.DisposableObserver;
import org.apache.flink.shaded.jackson2.com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.flink.shaded.jackson2.com.fasterxml.jackson.databind.node.ArrayNode;
import org.apache.flink.shaded.jackson2.com.fasterxml.jackson.databind.node.ObjectNode;

public class ShodanOps {

    private ShodanRestApi shodanQueryApi = new ShodanRestApi("$API_KEY");
    private ObjectMapper mapper = new ObjectMapper();
    private ObjectNode shodanResultNode = mapper.createObjectNode();

    public String queryShodan (String shodanQueryIP) {

        shodanQueryApi.hostByIp(shodanQueryIP).subscribe(new DisposableObserver<Host>() {
            @Override
            public void onNext(Host host) {
                shodanResultNode.put("shodan.host.isp", host.getIsp());
                shodanResultNode.put("shodan.host.os", host.getOs());
                ArrayNode shodanHostnameArray = mapper.valueToTree(host.getHostnames());
                shodanResultNode.putArray("shodan.host.hostname").addAll(shodanHostnameArray);
                ArrayNode shodanPortsArray = mapper.valueToTree(host.getPorts());
                shodanResultNode.putArray("shodan.host.port").addAll(shodanPortsArray);
                ArrayNode shodanCVEArray = mapper.valueToTree(host.getVulnerabilities());
                shodanResultNode.putArray("shodan.host.cve").addAll(shodanCVEArray);
            }

            @Override
            public void onError(Throwable throwable) {

            }

            @Override
            public void onComplete() {

            }
        });

        return shodanResultNode.toString();
    }
}
