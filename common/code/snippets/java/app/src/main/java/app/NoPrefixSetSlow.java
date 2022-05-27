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
     * Complete the 'noPrefix' function below.
     *
     * The function accepts STRING_ARRAY words as parameter.
     */

    public static void noPrefix(List<String> words) {
        Set<String> seenWords = new HashSet<>();
        for (int i = 0; i < words.size(); i++) {
            String candidate = words.get(i);
            String prefix = new String(candidate);
            while (!prefix.isEmpty()) {
                if (seenWords.contains(prefix)) {
                    System.out.println("BAD SET");
                    System.out.println(candidate);
                    return;
                }
                prefix = prefix.substring(0, prefix.length() - 1);
            }
            for (String seenWord : seenWords) {
                if (seenWord.startsWith(candidate)) {
                    System.out.println("BAD SET");
                    System.out.println(candidate);
                    return;
                }
            }
            seenWords.add(candidate);
        }
        System.out.println("GOOD SET");
    }

}

public class NoPrefixSetSlow {
    public static void main(String[] args) throws IOException {
        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(System.in));

        int n = Integer.parseInt(bufferedReader.readLine().trim());

        List<String> words = IntStream.range(0, n).mapToObj(i -> {
            try {
                return bufferedReader.readLine();
            } catch (IOException ex) {
                throw new RuntimeException(ex);
            }
        })
            .collect(toList());

        Result.noPrefix(words);

        bufferedReader.close();
    }
}
