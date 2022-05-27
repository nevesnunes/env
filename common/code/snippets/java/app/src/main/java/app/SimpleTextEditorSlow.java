package app;

import java.io.*;
import java.math.*;
import java.util.*;

class UndoState {
    public int operation = -1;
    public int k = -1;
    public List<Character> text;
}

public class SimpleTextEditorSlow {
    public static void main(String[] args) {
        List<Character> text = new ArrayList<>();
        List<UndoState> undoStates = new ArrayList<>();
        int undoIdx = -1;

        try (final BufferedReader reader = new BufferedReader(new InputStreamReader(System.in))) {
            int q = Integer.parseInt(reader.readLine());
            for (int i = 0; i < q; i++) {
                String[] tokens = reader.readLine().split(" ");
                int operation = Integer.parseInt(tokens[0]);
                switch(operation) {
                    case 1:
                        UndoState undoState = new UndoState();
                        undoState.operation = operation;
                        undoState.k = tokens[1].length();
                        undoStates.add(undoState);
                        undoIdx++;

                        for (Character c : tokens[1].toCharArray()) {
                            text.add(c);
                        }
                        break;
                    case 2:
                        int k = Integer.parseInt(tokens[1]);

                        undoState = new UndoState();
                        undoState.operation = operation;
                        undoState.text = new ArrayList<>(text.subList(text.size() - k, text.size()));
                        undoStates.add(undoState);
                        undoIdx++;

                        text = new ArrayList<>(text.subList(0, text.size() - k));
                        break;
                    case 3:
                        int at = Integer.parseInt(tokens[1]);
                        System.out.println(text.get(at - 1));
                        break;
                    case 4:
                        UndoState undoStateToApply = undoStates.get(undoIdx);
                        switch(undoStateToApply.operation) {
                            case 1:
                                text = text.subList(0, text.size() - undoStateToApply.k);
                                break;
                            case 2:
                                for (Character c : undoStateToApply.text) {
                                    text.add(c);
                                }
                                break;
                            default:
                                throw new RuntimeException("Unknown undo op " + operation);
                        }
                        undoStates.remove(undoIdx);
                        undoIdx--;
                        break;
                    default:
                        throw new RuntimeException("Unknown op " + operation);
                }
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
