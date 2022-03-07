/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.rocketmq.example.quickstart;

import org.apache.rocketmq.client.exception.MQClientException;
import org.apache.rocketmq.client.producer.DefaultMQProducer;
import org.apache.rocketmq.client.producer.SendResult;
import org.apache.rocketmq.common.message.Message;
import org.apache.rocketmq.remoting.common.RemotingHelper;

public class ProducerTest {
    public static void main(String[] args) throws MQClientException, InterruptedException {

        DefaultMQProducer producer = new DefaultMQProducer("jsy_test_group_name");

        /**
         * 通过代码指定名称服务器地址。producer.setNamesrvAddr("name-server1-ip:9876;name-server2-ip:9876");
         * 或者，您可以通过导出环境变量NAMESRV_ADDR来指定名称服务器地址
         * 采用配置环境变量方式
         */
        //producer.setNamesrvAddr("127.0.0.1:9876");

        producer.start();

        try {
            Message msg = new Message("jsy_test_topic1" /* Topic */,
                    "tag_one" /* Tag */,
                    ("jsy_test_topic tag_one 数据内容").getBytes(RemotingHelper.DEFAULT_CHARSET) /* Message body */
            );
            msg.setDelayTimeLevel(1);  //延时消设置
            SendResult sendResult = producer.send(msg);
            //producer.sendOneway(msg);
            System.out.printf("%s%n", sendResult);
        } catch (Exception e) {
            e.printStackTrace();
        }
        //producer.shutdown();
        //System.exit(0);
    }
}
