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
     * Complete the 'bfs' function below.
     *
     * The function is expected to return an INTEGER_ARRAY.
     * The function accepts following parameters:
     *  1. INTEGER n
     *  2. INTEGER m
     *  3. 2D_INTEGER_ARRAY edges
     *  4. INTEGER s
     */

    public static List<Integer> bfs(int n, int m, List<List<Integer>> edges, int s) {
        Map<Integer, List<Integer>> g = new HashMap<>();
        Set<Integer> seenNodes = new HashSet<>();
        for (List<Integer> edge : edges) {
            int parent = edge.get(0);
            int child = edge.get(1);
            seenNodes.add(parent);
            seenNodes.add(child);
            if (!g.containsKey(parent)) {
                g.put(parent, new ArrayList<>());
            }
            g.get(parent).add(child);
        }
        Queue<Integer> unreachableNodes = new ArrayDeque<>();
        for (int i = 1; i <= n; i++) {
            if (!seenNodes.contains(i)) {
                unreachableNodes.add(i);
            }
        }

        Stack<List<Integer>> stack = new Stack<>();
        stack.push(new ArrayList<>(Arrays.asList(s, 0)));
        List<Integer> weights = new ArrayList<>();
        while (!stack.isEmpty()) {
            List<Integer> state = stack.pop();
            int node = state.get(0);
            int d = state.get(1);
            int childDistance = d + 6;
            if (g.containsKey(node)) {
                for (int child : g.get(node)) {
                    while (!unreachableNodes.isEmpty() && unreachableNodes.peek() < child) {
                        weights.add(-1);
                        unreachableNodes.poll();
                    }
                    weights.add(childDistance);
                    stack.push(new ArrayList<>(Arrays.asList(child, childDistance)));
                }
            }
        }
        while (!unreachableNodes.isEmpty()) {
            weights.add(-1);
            unreachableNodes.poll();
        }
        return weights;
    }
}

public class WeightedBFSBad {
    public static void main(String[] args) throws IOException {
        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(System.in));
        BufferedWriter bufferedWriter = new BufferedWriter(new FileWriter(System.getenv("OUTPUT_PATH")));

        int q = Integer.parseInt(bufferedReader.readLine().trim());

        IntStream.range(0, q).forEach(qItr -> {
            try {
                String[] firstMultipleInput = bufferedReader.readLine().replaceAll("\\s+$", "").split(" ");

                int n = Integer.parseInt(firstMultipleInput[0]);

                int m = Integer.parseInt(firstMultipleInput[1]);

                List<List<Integer>> edges = new ArrayList<>();

                IntStream.range(0, m).forEach(i -> {
                    try {
                        edges.add(
                            Stream.of(bufferedReader.readLine().replaceAll("\\s+$", "").split(" "))
                                .map(Integer::parseInt)
                                .collect(toList())
                        );
                    } catch (IOException ex) {
                        throw new RuntimeException(ex);
                    }
                });

                int s = Integer.parseInt(bufferedReader.readLine().trim());

                List<Integer> result = Result.bfs(n, m, edges, s);

                bufferedWriter.write(
                    result.stream()
                        .map(Object::toString)
                        .collect(joining(" "))
                    + "\n"
                );
            } catch (IOException ex) {
                throw new RuntimeException(ex);
            }
        });

        bufferedReader.close();
        bufferedWriter.close();
    }
}
