package org.dragonservers.turing;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;

public class TuringNetworkListener implements Runnable{
    public static final int Port = 21947;
    public boolean AcceptingNewConnections = true;
    public ExecutorService ThreadPool;
    public ServerSocket serverSocket;
    public boolean shutdown = true;
    public final Object lock = new Object();
    //TODO
    @Override
    public void run() {
        //build the thread pool

        //TODO add this to some XML or JSON config file
        synchronized (lock){
            if(!shutdown){
                return;
            }
            shutdown = false;
            ThreadPool = Executors.newCachedThreadPool();


            try {
                System.out.println("[Turing Listener Thread] Starting");
                serverSocket = new ServerSocket(Port);
                System.out.println("[Turing Listener Thread] Listening on port " + Port);
                while (AcceptingNewConnections && Turing.running) {
                    Socket requestSocket = serverSocket.accept();
                    AssignConnection(requestSocket);
                }

            } catch (SocketException e) {
                System.out.println("Closing Connection");
            } catch (IOException e) {
                Turing.TuringLogger.log(Level.SEVERE, "ERROR While binding port\n Message:-" + e.getMessage(), e);
                System.out.println("[Turing Listener Thread] Critical Error ");
                e.printStackTrace();
                //return;
            }
            try {
                System.out.println("Waiting for Active Connection to Close ");
                boolean GraceFull = ThreadPool.awaitTermination(5, TimeUnit.SECONDS);
                ThreadPool.shutdown();
                if (GraceFull) {
                    System.out.println("Exited Gracefully");
                } else {
                    System.out.println("Connections Time out (not gracefully)");
                }

            } catch (InterruptedException e) {
                Turing.TuringLogger.log(Level.SEVERE, "ERROR While binding port\n Message:-" + e.getMessage(), e);
                System.out.println("[Turing Listener Thread] Critical Error ");
                e.printStackTrace();
            }
            shutdown = true;
        }
    }

    private void AssignConnection(Socket s) {
        ConnectionHandlerThread CHT = new ConnectionHandlerThread(s);
        ThreadPool.execute(CHT);
    }
}
