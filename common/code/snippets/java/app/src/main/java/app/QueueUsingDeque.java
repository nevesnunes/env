package app;

import java.io.*;
import java.math.*;
import java.util.*;

public class QueueUsingDeque {
    public static void main(String args[]) {
        final ArrayDeque<Integer> deque = new ArrayDeque<>();
        try (final BufferedReader reader = new BufferedReader(new InputStreamReader(System.in))) {
            int numQueries = Integer.parseInt(reader.readLine().trim());
            for (int i = 0; i < numQueries; i++) {
                String[] tokens = reader.readLine().split(" ");
                int queryType = Integer.parseInt(tokens[0]);
                switch(queryType) {
                    case 1:
                        int element = Integer.parseInt(tokens[1]);
                        deque.offer(element);
                        break;
                    case 2:
                        deque.poll();
                        break;
                    case 3:
                        System.out.println(deque.getFirst());
                        break;
                    default:
                        throw new RuntimeException("Unknown type: " + queryType);
                }
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}

