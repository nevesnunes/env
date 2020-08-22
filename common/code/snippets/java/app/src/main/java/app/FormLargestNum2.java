// Reference:
// http://www.shiftedup.com/2015/05/08/solution-to-problem-4

package app;

import java.util.*;
import java.util.stream.*;

public class FormLargestNum2 {
    public static void main(String args[]) {
        List<Integer> input = Arrays.stream(new int[] {420, 42, 423}).boxed().collect(Collectors.toList());
        Collections.sort(input, new FormLargestNumComparator());
        System.out.println(input.stream().map(i->Integer.toString(i)).reduce("", String::concat));
    }

    static class FormLargestNumComparator implements Comparator<Integer> {
        public int compare(Integer a, Integer b) {
            return ((""+a)+b).compareTo((""+b)+a) * -1;
        }
    }
}

