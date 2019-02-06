使用linux的raw socket演示TCP通信原理, 并不严谨
使用之前, 先执行以下指令, 否则, 系统通过RST消息拒绝连接
```
iptables -t filter -I OUTPUT -p tcp --dport 80 --tcp-flags RST RST -j DROP
```
主文件`main.cpp`




