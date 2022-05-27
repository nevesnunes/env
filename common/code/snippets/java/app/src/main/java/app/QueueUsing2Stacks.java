package app;

import java.io.*;
import java.math.*;
import java.util.*;

public class QueueUsing2Stacks {
    public static void main(String[] args) {
        final ArrayDeque<Integer> inbox = new ArrayDeque<>();
        final ArrayDeque<Integer> outbox = new ArrayDeque<>();

        try (final BufferedReader reader = new BufferedReader(new InputStreamReader(System.in))) {
            int numQueries = Integer.parseInt(reader.readLine().trim());
            for (int i = 0; i < numQueries; i++) {
                String[] tokens = reader.readLine().split(" ");
                int queryType = Integer.parseInt(tokens[0]);
                switch(queryType) {
                    case 2:
                    case 3:
                        if (outbox.isEmpty()) {
                            while (!inbox.isEmpty()) {
                                outbox.push(inbox.pop());
                            }
                        }
                }
                switch(queryType) {
                    case 1:
                        int element = Integer.parseInt(tokens[1]);
                        inbox.push(element);
                        break;
                    case 2:
                        outbox.pop();
                        break;
                    case 3:
                        System.out.println(outbox.peek());
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
