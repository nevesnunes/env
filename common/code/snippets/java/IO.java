package app;

import java.io.*;
import java.math.*;
import java.util.*;
import java.util.stream.*;

public class IO {
    public static void main(String args[]) {
        try (final BufferedReader reader = new BufferedReader(new InputStreamReader(System.in))) {
            int numQueries = Integer.parseInt(reader.readLine().trim());
            for (int i = 0; i < numQueries; i++) {
                String[] tokens = reader.readLine().split(" ");
                // ...
            }
        } catch (IOException e) {
            System.err.println(e);
        }
    }
}
