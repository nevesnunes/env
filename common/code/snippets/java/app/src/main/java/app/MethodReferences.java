package app;

import java.util.function.*; 

public class MethodReferences {
    public static String baz(Object o) {
        return "baz";
    }
    public static String message(Function<Object, String> f) {
        return f.apply(null);
    }
    public static void main(String args[]) {
        System.out.println(message(MethodReferences::baz));
    }
}

