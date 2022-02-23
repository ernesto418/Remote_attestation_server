package com.ifx.server.controller;

import java.util.Properties;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.json.JSONObject;

public class SecurityInfusion 
{
    public static void sendData(boolean status, String id, String v_id )
    {
        String topic = "infineon-attestation";
        Properties properties=new Properties();
	properties.put("bootstrap.servers", "col1.itml.gr:9093");
	properties.put("key.serializer", "org.apache.kafka.common.serialization.StringSerializer");
	properties.put("value.serializer", "org.apache.kafka.common.serialization.StringSerializer");
	properties.put("security.protocol","SSL");
	properties.put("ssl.truststore.location","/home/pi/Desktop/RemoteAttestation/Remote_attestation_server-Server_always_yes/server_remote/server/src/main/resources/certificatesKafka/truststore.jks");
	properties.put("ssl.truststore.password","kafka123");
	properties.put("ssl.keystore.location","/home/pi/Desktop/RemoteAttestation/Remote_attestation_server-Server_always_yes/server_remote/server/src/main/resources/certificatesKafka/keystore.jks");
	properties.put("ssl.keystore.password","kafka123");
	properties.put("ssl.key.password","kafka123");
	KafkaProducer<String,String> myProducer= new KafkaProducer<String,String>(properties);
	
	String message;
    	JSONObject item = new JSONObject();
    	item.put("ID", id);
    	item.put("V_ID", v_id);
    	item.put("Status", status);
    	message = item.toString();
    	
        try {
		myProducer.send(new  ProducerRecord<String, String>(topic,message));
	} catch (Exception e) {
		e.printStackTrace();
	}finally{
		myProducer.close();
	}
    }
}
