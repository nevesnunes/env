package app;

// Alternatives:
// - Considering leading zeros: https://stackoverflow.com/questions/12640280/combine-alphabetical-and-natural-order-aka-user-sane-sorting

import java.io.*;
import java.math.*;
import java.util.*;

class NaturalOrderComparator implements Comparator<String> {
    @Override
    public int compare(String o1, String o2) {
        int bias = 0;
        for (int i = 0; i < o1.length() && i < o2.length(); i++) {
            char o1c = o1.charAt(i);
            char o2c = o2.charAt(i);
            if (Character.isDigit(o1c) && !Character.isDigit(o2c)) {
                return 1;
            } else if (!Character.isDigit(o1c) && Character.isDigit(o2c)) {
                return -1;
            } else if (!Character.isDigit(o1c) && !Character.isDigit(o2c) && bias != 0) {
                return bias;
            }
            if (o1c < o2c) {
                bias = -1;
            } else if (o1c > o2c) {
                bias = 1;
            } else {
                bias = 0;
            }
        }
        if (o1.length() < o2.length()) {
            return -1;
        } else if (o1.length() > o2.length()) {
            return 1;
        }
        return bias;
    }
}

public class NaturalOrderComparison {
    public static void main(String args[]) {
        var a = Arrays.asList(
                "121.2.3.48",
                "21.12.3.4",
                "121.2.3.4",
                "22.2.3.4",
                "22.12.3.4",
                "1.2.3.4",
                "3.1.2.3",
                "1.1.2.3"
            );
        Collections.sort(a, new NaturalOrderComparator());
        System.out.println(a);
        Collections.sort(a, Comparator.naturalOrder());
        System.out.println(a);
        Collections.sort(a);
        System.out.println(a);
    }
}
