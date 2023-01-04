package x;

import java.util.Scanner;

public class Main {
    public static void main(String[] args) {
        Scanner in =new Scanner(System.in);
        int num1=in.nextInt();
        int num2=in.nextInt();
        String numStr=num1+"";


        StringBuilder sb=new StringBuilder();
        sb.append(numStr.charAt(0));
        sb.append(".");
        for(int i=1;i<num2+1;i++){
            sb.append(numStr.charAt(i));
        }
        sb.append("+");
        sb.append(numStr.length()-1);
        System.out.println(sb.toString());
    }
}
