package com.wzjwhut.example;

import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.Security;

public class Main {
    private final static Logger logger = LogManager.getLogger(Main.class);

    public static void main(String[] args) throws Throwable {
        ServerSocket ss = new ServerSocket(11234);
        while(true){
            Socket s = ss.accept();
            s.setTcpNoDelay(true);
            OutputStream out = s.getOutputStream();
            byte[] buf = new byte[1024];
            while(true){
                out.write(buf);
                logger.info("write");
            }
        }

    }


}
