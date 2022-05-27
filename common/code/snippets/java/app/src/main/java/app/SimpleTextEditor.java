package app;

import java.io.*;
import java.util.*;


class UndoState {
    public int operation = -1;
    public int k = -1;
    public String text;
}

public class SimpleTextEditor {
    public static void main(String[] args) {
        StringBuilder text = new StringBuilder();
        List<UndoState> undoStates = new ArrayList<>();
        int undoIdx = -1;

        try (final BufferedReader reader = new BufferedReader(new InputStreamReader(System.in))) {
            int q = Integer.parseInt(reader.readLine());
            for (int i = 0; i < q; i++) {
                String[] tokens = reader.readLine().split(" ");
                int operation = Integer.parseInt(tokens[0]);
                int textLen = text.length();
                switch(operation) {
                    case 1:
                        UndoState undoState = new UndoState();
                        undoState.operation = operation;
                        undoState.k = tokens[1].length();
                        undoStates.add(undoState);
                        undoIdx++;

                        text.append(tokens[1]);
                        break;
                    case 2:
                        int k = Integer.parseInt(tokens[1]);
                        undoState = new UndoState();
                        undoState.operation = operation;
                        undoState.text = text.subSequence(textLen - k, textLen).toString();
                        undoStates.add(undoState);
                        undoIdx++;

                        text = text.delete(textLen - k, textLen);
                        break;
                    case 3:
                        int at = Integer.parseInt(tokens[1]);
                        System.out.println(text.charAt(at - 1));
                        break;
                    case 4:
                        UndoState undoStateToApply = undoStates.get(undoIdx);
                        switch(undoStateToApply.operation) {
                            case 1:
                                text = text.delete(textLen - undoStateToApply.k, textLen);
                                break;
                            case 2:
                                text.append(undoStateToApply.text);
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
