package app;

import java.io.*;
import java.math.*;
import java.security.*;
import java.text.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.*;
import java.util.regex.*;
import java.util.stream.*;
import static java.util.stream.Collectors.joining;
import static java.util.stream.Collectors.toList;

public class PairsWithUniqueElementsSlow {

    /*
     * Complete the 'pairs' function below.
     *
     * The function is expected to return an INTEGER.
     * The function accepts following parameters:
     *  1. INTEGER k
     *  2. INTEGER_ARRAY arr
     */

    public static int pairs(int k, List<Integer> arr) {
        Map<Integer, Set<Integer>> seenMatches = new HashMap<>();
        int matches = 0;
        for (int i = 0; i < arr.size(); i++) {
            int a = arr.get(i);
            for (int j = 0; j < arr.size(); j++) {
                if (!seenMatches.containsKey(i)) {
                    seenMatches.put(i, new HashSet<Integer>());
                }
                if (!seenMatches.containsKey(j)) {
                    seenMatches.put(j, new HashSet<Integer>());
                }
                if (seenMatches.get(i).contains(j)) {
                    continue;
                }
                if (seenMatches.get(j).contains(i)) {
                    continue;
                }
                seenMatches.get(i).add(j);
                seenMatches.get(j).add(i);

                int b = arr.get(j);
                int v = Math.abs(a - b);
                if (k == v) {
                    matches++;
                }
            }
        }
        return matches;
    }

}
public class Solution {
    public static void main(String[] args) throws IOException {
        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(System.in));
        BufferedWriter bufferedWriter = new BufferedWriter(new FileWriter(System.getenv("OUTPUT_PATH")));

        String[] firstMultipleInput = bufferedReader.readLine().replaceAll("\\s+$", "").split(" ");

        int n = Integer.parseInt(firstMultipleInput[0]);

        int k = Integer.parseInt(firstMultipleInput[1]);

        List<Integer> arr = Stream.of(bufferedReader.readLine().replaceAll("\\s+$", "").split(" "))
            .map(Integer::parseInt)
            .collect(toList());

        int result = Result.pairs(k, arr);

        bufferedWriter.write(String.valueOf(result));
        bufferedWriter.newLine();

        bufferedReader.close();
        bufferedWriter.close();
    }
}
