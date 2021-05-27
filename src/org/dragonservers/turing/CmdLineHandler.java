package org.dragonservers.turing;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;

public class CmdLineHandler implements Runnable{
    public BufferedReader br;
    private List<String> MsgQue;

    //TODO add help
    //TODO save
    //
    public void QueueMessage(String msg){
        MsgQue.add(msg);
    }
    @Override
    public void run() {
        br = new BufferedReader(new InputStreamReader(System.in));
        MsgQue = new ArrayList<>();
        while(Turing.running){
            try {
                if(br.ready()){
                    //TODO handle user input
                    String input = br.readLine();
                    //TODO Proper ShutDown
                    switch (input.toLowerCase()) {
                        case "quit" -> {
                           Turing.Quit();
                        }
                        case "get conc" -> System.out.println("Not yet Supported");
                        case "save" ->{
                            synchronized (Turing.TuringSH.lockObject) {
                                Turing.TuringSH.saveNow = true;
                            }
                        }
                        case "code" ->{
                            System.out.println("Generating... ");
                            RegistrationCode tmp = Turing.CodeFac.GenerateCode();
                            System.out.println("CODE = " + tmp.getCode());
                            System.out.println("Done");
                        }
                        case "list users" ->{
                            System.out.println("#Users");
                            String[] ans = Turing.EUserFac.GetUserBase();
                            for (String username :
                                    ans) {
                                System.out.println(" -" + username);
                            }
                        }
                        default -> System.out.println("Invalid command");
                    }
                }
            } catch (IOException e) {
                Turing.TuringLogger.log(Level.SEVERE,"IO Exception while Reading Input From Admin",e);
            }
            while (!MsgQue.isEmpty()){
                System.out.println(MsgQue.get(0));
                MsgQue.remove(0);
            }
        }

    }
}
