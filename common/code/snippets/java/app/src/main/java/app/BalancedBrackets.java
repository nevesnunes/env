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

public class BalancedBrackets {
    public static String isBalanced(String s) {
        final Map<Character, Character> matches = new HashMap<>();
        matches.put(')', '(');
        matches.put('}', '{');
        matches.put(']', '[');
        final ArrayDeque<Character> seenBrackets = new ArrayDeque<>();
        final Set<Character> openingBrackets = new HashSet<>(matches.values());

        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (openingBrackets.contains(c)) {
                seenBrackets.push(c);
            } else {
                if (seenBrackets.isEmpty()) {
                    return "NO";
                }
                char lastSeenOpeningBracket = seenBrackets.pop();
                if (!matches.get(c).equals(lastSeenOpeningBracket)) {
                    return "NO";
                }
            }
        }
        if (!seenBrackets.isEmpty()) {
            return "NO";
        }
        return "YES";
    }

}

public class Solution {
    public static void main(String[] args) throws IOException {
        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(System.in));
        BufferedWriter bufferedWriter = new BufferedWriter(new FileWriter(System.getenv("OUTPUT_PATH")));

        int t = Integer.parseInt(bufferedReader.readLine().trim());

        IntStream.range(0, t).forEach(tItr -> {
            try {
                String s = bufferedReader.readLine();

                String result = Result.isBalanced(s);

                bufferedWriter.write(result);
                bufferedWriter.newLine();
            } catch (IOException ex) {
                throw new RuntimeException(ex);
            }
        });

        bufferedReader.close();
        bufferedWriter.close();
    }
}
