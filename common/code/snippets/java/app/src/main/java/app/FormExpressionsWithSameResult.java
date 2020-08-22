// Reference:
// http://www.shiftedup.com/2015/05/08/solution-to-problem-5-and-some-other-thoughts-about-this-type-of-questions

package app;

import java.util.*;

public class FormExpressionsWithSameResult {
    public static <T> Set<Set<T>> powerSet(Set<T> originalSet) {
        Set<Set<T>> sets = new HashSet<Set<T>>();
        if (originalSet.isEmpty()) {
            sets.add(new HashSet<T>());
            return sets;
        }
        List<T> list = new ArrayList<T>(originalSet);
        T head = list.get(0);
        Set<T> rest = new HashSet<T>(list.subList(1, list.size()));
        for (Set<T> set : powerSet(rest)) {
            Set<T> newSet = new HashSet<T>();
            newSet.add(head);
            newSet.addAll(set);
            sets.add(newSet);
            sets.add(set);
        }
        return sets;
    }

    public static <T> Set<Set<String>> orderedSubSets(Set<T> originalSet) {
        Set<Set<String>> sets = new HashSet<Set<String>>();
        if (originalSet.isEmpty()) {
            sets.add(new HashSet<>());
            return sets;
        }
        List<T> list = new ArrayList<>(originalSet);
        int subListIndex = 1;
        int listLength = list.size();
        for(; subListIndex <= listLength; subListIndex++) {
            Set<T> head = new HashSet<>(list.subList(0, subListIndex));
            String reducedHead = head.stream().map(Object::toString).reduce("", String::concat);
            Set<T> rest = new HashSet<>(list.subList(subListIndex, listLength));
            for (Set<String> set : orderedSubSets(rest)) {
                Set<String> newSet = new HashSet<>();
                newSet.add(reducedHead);
                for (String s : set) {
                    newSet.add(s);
                }
                sets.add(newSet);
                sets.add(set);
            }
        }
        return sets;
    }

    public static void eval(Set<String> subSetIndexes, Set<String> negativeIndexes, List<String> values, int expectedResult) {
        List<Integer> mappedSubSetValues = new ArrayList<>();
        for (String s : subSetIndexes) {
            String newValue = "";
            for (char c : s.toCharArray()) {
                newValue += values.get(Integer.parseInt("" + c) - 1);
            }
            mappedSubSetValues.add(Integer.parseInt(newValue));
        }
        int length = mappedSubSetValues.size();
        for (String s : negativeIndexes) {
            int parsedNegativeIndex = Integer.parseInt(s);
            if (parsedNegativeIndex > length - 1) {
                // available elements do not match all required indexes
                return;
            } else {
                int newValue = -1 * mappedSubSetValues.get(parsedNegativeIndex);
                mappedSubSetValues.set(parsedNegativeIndex, newValue);
            }
        }
        int result = 0;
        for (int i : mappedSubSetValues) {
            result += i;
        }
        if (result == expectedResult) {
            System.out.println(toString(mappedSubSetValues));
        }
    }

    public static String toString(List<Integer> values) {
        Collections.sort(values, AbsComparator.instance);
        String out = "";
        for (int i : values) {
            if (i > 0) {
                out += "+";
            }
            out += i;
        }
        return out;
    }

    public static class AbsComparator implements Comparator<Integer> {
        public static final AbsComparator instance = new AbsComparator();
        public int compare(Integer a, Integer b) {
            return Integer.toString(Math.abs(a)).compareTo(Integer.toString(Math.abs(b)));
        }
    }

    public static void main(String args[]) {
        int expectedResult = 100;
        int[] numbers = new int[] {1, 2, 3, 4, 5, 6, 7, 8, 9};
        int length = numbers.length;
        List<String> myList = new ArrayList<>();
        for (int i = 0; i < length; i++) {
            myList.add(Integer.toString(numbers[i]));
        }
        Set<String> mySet = new HashSet<>(myList);
        for (Set<String> subSetIndexes : orderedSubSets(mySet)) {
            for (Set<String> negativeIndexes : powerSet(mySet)) {
                eval(subSetIndexes, negativeIndexes, myList, expectedResult);
            }
        }
    }
}
