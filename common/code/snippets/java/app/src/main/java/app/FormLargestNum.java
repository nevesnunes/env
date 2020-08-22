// Reference:
// http://www.shiftedup.com/2015/05/08/solution-to-problem-4

package app;

import java.util.*;
import java.util.stream.*;

public class FormLargestNum {
    public static void main(String args[]) {
        List<Integer> input = Arrays.stream(new int[] {420, 42, 423}).boxed().collect(Collectors.toList());
        Collections.sort(input, new FormLargestNumComparator());
        System.out.println(input.stream().map(i->Integer.toString(i)).reduce("", String::concat));
    }

    static class FormLargestNumComparator implements Comparator<Integer> {
        public int compare(Integer a, Integer b) {
            char[] ca = Integer.toString(a).toCharArray();
            char[] cb = Integer.toString(b).toCharArray();
            for (int i = 0; i < ca.length && i < cb.length; i++) {
                if (ca[i] > cb[i]) {
                    return -1;
                } else if (ca[i] < cb[i]) {
                    return 1;
                } else if (ca.length < cb.length) {
                    if (ca[i] < cb[i+1]) {
                        return 1;
                    } else {
                        return -1;
                    }
                } else if (ca.length > cb.length) {
                    if (ca[i+1] > cb[i]) {
                        return -1;
                    } else {
                        return 1;
                    }
                }
            }
            return 0;
        }
    }
}

