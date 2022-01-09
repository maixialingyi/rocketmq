本地启动测试: https://blog.csdn.net/weixin_43073775/article/details/109016093
创建生产端或消费端需配置   producer.setNamesrvAddr("127.0.0.1:9876");  环境变量读取不到
启动 org.apache.rocketmq.namesrv.NamesrvStartup
启动 org.apache.rocketmq.broker.BrokerStartup
控制台启动 java -jar rocketmq-console-ng-1.0.1.jar --server.port=8080 --rocketmq.config.namesrvAddr=127.0.0.1:9876
访问    
快速示例 org.apache.rocketmq.example.quickstart

生产端:
同步发送 org.apache.rocketmq.example.simple.Producer
异步发送 org.apache.rocketmq.example.simple.AsyncProducer
单项发送 producer.sendOneway(); 自己写

消费端:
push推送模式 org.apache.rocketmq.example.simple.PushConsumer
推其实是封装了拉模式offset操作
pull拉模式   org.apache.rocketmq.example.simple.LitePullConsumer

顺序消息:    org.apache.rocketmq.example.ordermessage

