// Reference:
// http://www.shiftedup.com/2015/05/08/solution-to-problem-5-and-some-other-thoughts-about-this-type-of-questions

package app;

import java.util.*;

public class FormExpressionsWithSameResult2 {
    private static int TARGET_SUM = 100;
    private static int[] VALUES = { 1, 2, 3, 4, 5, 6, 7, 8, 9 };

    static ArrayList<String> add(int digit, String sign, ArrayList<String> branches) {
        for (int i = 0; i < branches.size(); i++) {
            branches.set(i, digit + sign + branches.get(i));
        }
        return branches;
    }

    static ArrayList<String> f(int sum, int number, int index) {
        int digit = Math.abs(number % 10);
        if (index >= VALUES.length) {
            if (sum == number) {
                ArrayList<String> result = new ArrayList<String>();
                result.add(Integer.toString(digit));
                return result;
            } else {
                return new ArrayList<String>();
            }
        }
        ArrayList<String> branch1 = f(sum - number, VALUES[index], index + 1);
        ArrayList<String> branch2 = f(sum - number, -VALUES[index], index + 1);
        int concatenatedNumber = number >= 0
            ? 10 * number + VALUES[index]
            : 10 * number - VALUES[index];
        ArrayList<String> branch3 = f(sum, concatenatedNumber, index + 1);
        ArrayList<String> results = new ArrayList<String>();
        results.addAll(add(digit, "+", branch1));
        results.addAll(add(digit, "-", branch2));
        results.addAll(add(digit, "", branch3));
        return results;
    }

    public static void main(String[] args) {
        for (String string : f(TARGET_SUM, VALUES[0], 1)) {
            System.out.println(string);
        }
    }
}
