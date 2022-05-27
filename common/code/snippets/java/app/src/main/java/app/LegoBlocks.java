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

class Result {

    /*
     * Complete the 'legoBlocks' function below.
     *
     * The function is expected to return an INTEGER.
     * The function accepts following parameters:
     *  1. INTEGER n
     *  2. INTEGER m
     */
    private static final List<Integer> allRowPermutations;
    private static final Map<Integer, List<Integer>> cacheGoodLayouts = new HashMap<>();
    private static final Map<Integer, List<Integer>> cacheTotalLayouts = new HashMap<>();

    static {
        // By inspection, we know that
        // P(1) = 1, P(2) = 2, P(3) = 4, and P(4) = 8.
        // For any m > 4, we can consider four different cases:
        // * 1. The last block has width 1, in which case the remainder
        //   of the row has width m-1 and thus P(m-1) possible layouts.
        // * 2. The last block has width 2, in which case the remainder
        //   of the row has width m-2 and thus P(m-2) possible layouts.
        // * 3. The last block has width 3, in which case the remainder
        //   of the row has width m-3 and thus P(m-3) possible layouts.
        // * 4. The last block has width 4, in which case the remainder
        //   of the row has width m-4 and thus P(m-4) possible layouts.
        allRowPermutations = new ArrayList<>(Arrays.asList(0, 1, 2, 4, 8));
        for (int i = 5; i < 1001; i++) {
            allRowPermutations.add(
                allRowPermutations.get(i - 1) +
                allRowPermutations.get(i - 2) +
                allRowPermutations.get(i - 3) +
                allRowPermutations.get(i - 4)
            );
        }
    }

    public static int legoBlocks(int n, int m) {
        if (m == 1) {
            return 1;
        }
        if (n == 1) {
            if (m < 5) {
                return 1;
            } else {
                return 0;
            }
        }

        final int upper = 1_000_000_000 + 7;
        List<Integer> goodLayouts = new ArrayList<>(Arrays.asList(0, 1));
        List<Integer> totalLayouts = new ArrayList<>(Arrays.asList(0, 1));
        int start = 2;

        // Memoization
        if (cacheGoodLayouts.containsKey(n)) {
            goodLayouts = cacheGoodLayouts.get(n);
            if (goodLayouts.size() > m) {
                return goodLayouts.get(m);
            }
            totalLayouts = cacheTotalLayouts.get(n);
            start = goodLayouts.size();
        }

        // Since each row is independent from each other, we can
        // affirm that the total number of layouts of a wall of
        // height n and width m is P(m)^n
        for (int i = start; i < m + 1; i++) {
            totalLayouts.add(
                (int) Math.pow(allRowPermutations.get(i), n) % upper
            );
        }
        cacheTotalLayouts.put(n, totalLayouts);

        // To find the number of good layouts for a wall of
        // height n and width m, we still have to subtract                     // the number of bad layouts from allRowPermutations(m)^n
        for (int i = start; i < m + 1; i++) {
            // Consider a wall of height n, width m, with a
            // straight line running from top to bottom at the
            // leftmost position (i.e. the blocks on the leftmost
            // position of each row are all of length 1).
            //
            // The number of bad layouts that satisfy this                         // condition is S(n,1) * P(m-1)^n, since to the left
            // of the line there are S(n,1) good layouts
            // (there are no bad layouts for m = 1), and to
            // its right we have P(m-1)^n layouts (good + bad).
            //
            // We continue then moving the line to the right and
            // counting the bad layouts, which will yield at the
            // end D(n,m) = sum_(i=1)^(m-1) S(n,i) * P(m-1)^n.
            goodLayouts.add(totalLayouts.get(i));
            for (int j = 0; j < i; j++) {
                goodLayouts.set(i, goodLayouts.get(i) -
                    goodLayouts.get(j) * totalLayouts.get(i - j)
                );
            }
            goodLayouts.set(i, (int) goodLayouts.get(i) % upper);
        }
        cacheGoodLayouts.put(n, goodLayouts);

        return (int) goodLayouts.get(m) % upper;
    }

}

public class LegoBlocks {
    public static void main(String[] args) throws IOException {
        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(System.in));
        BufferedWriter bufferedWriter = new BufferedWriter(new FileWriter(System.getenv("OUTPUT_PATH")));

        int t = Integer.parseInt(bufferedReader.readLine().trim());

        IntStream.range(0, t).forEach(tItr -> {
            try {
                String[] firstMultipleInput = bufferedReader.readLine().replaceAll("\\s+$", "").split(" ");

                int n = Integer.parseInt(firstMultipleInput[0]);

                int m = Integer.parseInt(firstMultipleInput[1]);

                int result = Result.legoBlocks(n, m);

                bufferedWriter.write(String.valueOf(result));
                bufferedWriter.newLine();
            } catch (IOException ex) {
                throw new RuntimeException(ex);
            }
        });

        bufferedReader.close();
        bufferedWriter.close();
    }
}
