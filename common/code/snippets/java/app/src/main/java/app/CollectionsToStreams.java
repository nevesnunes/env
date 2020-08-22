package app;

import java.util.*;
import java.util.stream.*;

public class CollectionsToStreams {
    public static void main(String[] args) {
        // https://www.baeldung.com/convert-array-to-set-and-set-to-array
        String[] sourceArray = { "0", "1", "2", "3", "4", "5" };
        Set<String> targetSet = new HashSet<>(Arrays.asList(sourceArray));
        targetSet.stream().filter((e) -> {
            return Integer.parseInt(e) > 0;
        }).forEach(System.out::println);

        // https://www.baeldung.com/java-initialize-hashmap
        Object[][] input = new Object[][] {
            { "data1", 1 },
            { "data2", 2 },
        };
        Map<String, Integer> map;

        System.out.println("map stream collect: reverse order");
        map = Stream.of(input).collect(Collectors.toMap(
                    data -> (String) data[0],
                    data -> (Integer) data[1]));
        map.entrySet().stream().forEach((e) -> {
            System.out.println(String.format(
                    "%s:%s",
                    e.getKey(),
                    e.getValue()));
        });

        System.out.println("map stream collect: preserve order");
        Stream.of(input).flatMap(Arrays::stream)
        .forEach((e) -> {
            System.out.println(String.format(
                    "%s:%s",
                    e, 0));
        });
        map = Stream.of(input).flatMap(Arrays::stream)
            .collect(Collectors.toMap(
                    // Function.identity(),
                    // Function.identity(),
                    String.class::cast,
                    Integer.class::cast,
                    // http://hg.openjdk.java.net/jdk8/jdk8/jdk/file/687fd7c7986d/src/share/classes/java/util/stream/Collectors.java#l122
        (u, v) -> {
            throw new IllegalStateException(String.format("Duplicate key %s", u));
        },
        LinkedHashMap::new));
        map.entrySet().stream().forEach((e) -> {
            System.out.println(String.format(
                    "%s:%s",
                    e.getKey(),
                    e.getValue()));
        });
    }
}
