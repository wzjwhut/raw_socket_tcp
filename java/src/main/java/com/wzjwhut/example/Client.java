package com.wzjwhut.example;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.net.Socket;

public class Client {
    private final static Logger logger = LogManager.getLogger(Client.class);

    private final static byte[] rawMessage = "hello world".getBytes();

    public static void main(String[] args) throws Throwable {
        Socket socket = new Socket("115.28.94.100", 11234);
        socket.setTcpNoDelay(true);
        socket.getOutputStream();
        socket.getInputStream();
        socket.setSoLinger(true, -1);
        logger.info("lingner: {}", socket.getSoLinger());
        socket.getInputStream().read();
        while(true){
            Thread.sleep(1000);
        }
    }


}
