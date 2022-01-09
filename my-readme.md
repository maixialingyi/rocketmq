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
广播消息:    org.apache.rocketmq.example.broadcast  推送到所有消费端,所有消费端都消费一遍
延迟消息:    msg.setDelayTimeLevel();  设置延时  
            开源版本只支持 1S后 3S后等18个时长, 不支持任意时间点设置                如果用开源这是个改造点
批量消息     org.apache.rocketmq.example.batch   消息大小有限制1M,同topic,不能是延时/事务消息
过滤消息     org.apache.rocketmq.example.filter    tag / sql 两种, 由broker过滤
事务消息     回查时间,次数可配置
权限        docs/cn/acl
消息轨迹


