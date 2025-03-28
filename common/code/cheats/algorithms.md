# +

- https://www.baeldung.com/java-collections-complexity

- https://github.com/fragglet/c-algorithms
- http://fxr.watson.org/fxr/source/sys/queue.h
    - https://github.com/TaborKelly/queue-example/blob/master/queue_example.c

- [GitHub \- VAR\-solutions/Algorithms: A repository of different Algorithms and Data Structures implemented in many programming languages\.](https://github.com/VAR-solutions/Algorithms)

- ~/code/doc/algorithms/CLRS-3rd.pdf
- ~/code/doc/algorithms/CLRS-3rd-Solutions.pdf
- ~/code/doc/algorithms/TheAlgorithmDesignManual.pdf
- https://en.wikipedia.org/wiki/List_of_logarithmic_identities

- [Developer Roadmaps](https://roadmap.sh/)
- [GitHub \- tayllan/awesome\-algorithms: A curated list of awesome places to learn and/or practice algorithms\.](https://github.com/tayllan/awesome-algorithms)
- [GitHub \- TSiege/Tech\-Interview\-Cheat\-Sheet: Studying for a tech interview sucks\. Here&\#39;s an open source cheat sheet to help](https://github.com/TSiege/Tech-Interview-Cheat-Sheet)
- [Algorithms and Data Structures Cheatsheet](https://algs4.cs.princeton.edu/cheatsheet/)
- [Algorithms for Modern Hardware \- Algorithmica](https://en.algorithmica.org/hpc/)

- https://news.ycombinator.com/item?id=7953725
    - https://en.wikipedia.org/wiki/Cycle_detection#Floyd's_Tortoise_and_Hare
- https://en.wikipedia.org/wiki/Karatsuba_algorithm
- https://en.wikipedia.org/wiki/Log-structured_merge-tree
    - optimize access to disks by writing append-only

- string processing
    - LZW algorithm
    - longest common subsequence algorithm
- tree graph processing
    - post order depth first search
- list processing
    - group elements in an array into sub arrays of length k
- integer processing
    - change of radix algorithm (e.g. change a number from base 10 to base 2)
- array list, linked list, hash map, set, stack, heap, queue

# Sorts

```
Algorithm      Time Complexity                           Space Complexity
               Best        Average        Worst          Worst
Quicksort      Ω(n log(n)) Θ(n log(n))    O(n^2)         O(log(n))
Mergesort      Ω(n log(n)) Θ(n log(n))    O(n log(n))    O(n)
Timsort        Ω(n)        Θ(n log(n))    O(n log(n))    O(n)
Heapsort       Ω(n log(n)) Θ(n log(n))    O(n log(n))    O(1)
Bubble Sort    Ω(n)        Θ(n^2)         O(n^2)         O(1)
Insertion Sort Ω(n)        Θ(n^2)         O(n^2)         O(1)
Selection Sort Ω(n^2)      Θ(n^2)         O(n^2)         O(1)
Tree Sort      Ω(n log(n)) Θ(n log(n))    O(n^2)         O(n)
Shell Sort     Ω(n log(n)) Θ(n(log(n))^2) O(n(log(n))^2) O(1)
Bucket Sort    Ω(n+k)      Θ(n+k)         O(n^2)         O(n)
Radix Sort     Ω(nk)       Θ(nk)          O(nk)          O(n+k)
Counting Sort  Ω(n+k)      Θ(n+k)         O(n+k)         O(k)
Cubesort       Ω(n)        Θ(n log(n))    O(n log(n))    O(n)
```

- Selection Sort
    - go through array, updating minimum
    - switch minimum with last ordered index+1
    - impl.
        ```c
        selection_sort(int s[], int n) {
            int i,j; /* counters */
            int min; /* index of minimum */
            for (i=0; i<n; i++) {
                min=i;
                for (j=i+1; j<n; j++)
                    if (s[j] < s[min]) min=j;
                swap(&s[i],&s[min]);
            }
        }
        ```
    - big-o
        ```
        S(n) = Sum(from: i=0, to: n-1, body:
            Sum(from: j=i+1, to: n-1, body: 1)
        ) =
        Sum(from: i=0, to: n-1, body: n-i-1) =
        n(n-1)/2

        S(n) <= n(n-1) = O(n^2)
        S(n) >= (n/2)(n/2) = Omega(n^2)
        ```

- Insertion Sort
    - compare current index with last ordered index
        - if smaller
            - switch
                - then current index + 1
        - else
            - last ordered index - 1 until beginning
                - then current index + 1

- Bubble Sort
    - pairwise compare indexes
        - if smaller is last index
            - switch
    - last element will be ordered
        - then loop for length - 1
    - => use bool for swapped (stop condition)
    - :) Good for seeing already sorted

- Merge Sort
    - Subdivide list
        - Merge each sub list
            - copy both sub lists into helper array
            - compare one index from each sub list
                - if index of sub list -lt other index, then assign to original array
    - :) Good for single linked lists (only +1 extra space)
    - :) Access contiguous memory locations
    - :) Parallelization

- Heap Sort
    - heapify => ensuring child is smaller than parent
    - Extract maximum from heap
        - Redo heapify

- Quick Sort
    - 1-pivot vs. dual-pivot
        - https://docs.oracle.com/javase/7/docs/api/java/util/Arrays.html#sort(byte[])
    ```python
    def quickSort(arr, left, right):
        if left < right:
            pivot = partition(arr, left, right)
            quickSort(arr, left, pivot - 1)
            quickSort(arr, pivot, right)
        return arr
    def partition(arr, left, right):
        pivot = arr[(left + right) // 2]
        while left <= right:
            while arr[left] < pivot: left += 1
            while arr[right] > pivot: right -= 1
            if left <= right:
                (arr[left], arr[right]) = (arr[right], arr[left])
                left += 1
                right -= 1
        return left
    ```

- Counting sort
    - index array (length = largest value) -> store counts of each index
    - loop index array -> pos i+1 = value i + value i+1
    - output array -> loop initial array from end
        - i value -> lookup index array = i value
            - output-index = value-1 in index-array
            - output-value = index in index-array
    - :) eliminate duplicates

- Radix sort
    - :) O(kn) can be better than O(n log(n)), n = count_elements, k = count_passes

# Linked List

```c
Node deleteNote(Node head, int d) {
    Node n = head;
    if (n.data == d) {
        return head.next;
    }
    while (n.next != null) {
        if (n.next.data == d) {
            n.next = n.next.next;
            return head;
        }
        n = n.text;
    }
    return head;
}
```

# Binary Search

```java
Collections.sort(list, Collections.reverseOrder());
// Output: [E, D, C, B, A]

int index = Collections.binarySearch(list, "D", Collections.reverseOrder());
// Output: 1
```

# Trees

- binary tree - each node has up to 2 children
- binary search tree - ordered
    - ? duplicates cases: unsupported, left ordered or right ordered
    ```
    foreach node n, left_descendents <= n < right_descendents
    ```
- complete binary tree - each level is filled, with optional rightmost children in last level missing
- full binary tree - each node has 0 or 2 children
- perfect binary tree - full and complete

```c
// traversal
void preOrderTraversal(TreeNode node) {
    if (node != null) {
        // preOrder
        visit(node);
        preOrderTraversal(node.left);
        // inOrder
        // visit(node);
        preOrderTraversal(node.right);
        // postOrder
        // visit(node);
    }
}
```

### Binary Heaps

- min-heap - each node is smaller than children
- max-heap - each node is larger than children

```java
public class MaxComparator implements Comparator<Integer> {
    public int compare( Integer x, Integer y ) {
        return y - x;
    }
}
PriorityQueue maxHeap = new PriorityQueue(size, new MaxComparator());
```

- insert()
    - at rightmost bottom position, ensuring complete tree property
    - swap new node with parent, until ensuring min-heap property
    - O(log n)
- extract_minimum()
    - remove root node
    - move bottommost rightmost node to root
    - swap new root node with smallest child, until ensuring min-heap property
    - O(log n)
- delete()
    - O(n)

- https://www.geeksforgeeks.org/min-heap-in-java/
- https://www.geeksforgeeks.org/min-heap-in-python/

### Trie

- stores words where shared prefixes share same parents
- find()
    - O(k), k = length of prefix

- https://github.com/naskitis/B-trie

### Balanced Trees

- ensures O(log n) runtime for insert() and find()
    - ! left and right subtrees could have diff sizes

balancing
```c
link balanceR(link h) {
  if (h->N < 2)
    return h;
  h = partR(h, h->N/2);
  h->l = balanceR(h->l);
  h->r = balanceR(h->r);
  return h;
}
```
```java
// Traverse the skewed binary tree and stores its nodes pointers in vector nodes[]
void storeBSTNodes(Node root, Vector<Node> nodes)  {
    if (root == null)
        return;

    // Store nodes inorder (= sorted order for BST)
    storeBSTNodes(root.left, nodes);
    nodes.add(root);
    storeBSTNodes(root.right, nodes);
}
Node buildTree(List<Node> nodes, int start, int end) {
    if (start > end)
        return null;

    // Get the middle element and make it root
    int mid = (start + end) / 2;
    Node node = nodes.get(mid);

    // Using index inorder, construct left and right subtrees
    node.left = buildTreeUtil(nodes, start, mid - 1);
    node.right = buildTreeUtil(nodes, mid + 1, end);

    return node;
}
```

validating heights

```java
public boolean isBalanced(TreeNode root) {
    if (root == null)
        return true;
    if (getHeight(root) == -1)
        return false;
    return true;
}
public int getHeight(TreeNode root) {
    if (root == null)
        return 0;
    int left = getHeight(root.left);
    int right = getHeight(root.right);
    if (left == -1 || right == -1)
        return -1;
    if (Math.abs(left - right) > 1) {
        return -1;
    }
    return Math.max(left, right) + 1;
}
```

- https://www.programcreek.com/2013/02/leetcode-balanced-binary-tree-java/

- B-tree
    - structure fully in memory
    - :) performant caching - consider cache line sizes (or VM pages)

- AVL
    - diff height between children -lt 2

- Red-Black
    - :( keeping the colour in every tree node bloats the data – quite probably by 8 bytes for the struct size on a modern machine, and many malloc libraries round up to the next multiple or 16 or 32 bytes
    - Insert, delete and search: Average case: O(log n), Worst Case: O(log n)

- scapegoat tree
    - :) vs. red-black - requires only a few bytes of extra global storage (for powers of your acceptable unbalance factor)

- R-tree
    - indexing multi-dimensional information such as geographical coordinates, rectangles or polygons

# Graphs

- storing
    - adjacency matrix - read order = row-column
    - adjacency list ~= hash table where hash() = node id
- marking
    - white = un-visited
    - grey = visited
    - black = finished (no more children to visit)

- back edge = points to gray node
- forward edge = points to black node

- Breadth-First Search (BFS)
    - use case - path between two nodes (quicker for less deep paths)
    - => bidirectional search (BFS started from both nodes)
        - `O(k^d) vs. O(2*k^(d/2))`, k = count_adjacent_nodes, d = path_length
    ```cpp
    void search(Node root, int current_time = 0) {
        Queue q = new Queue();
        q.enqueue(root);
        while (!q.isEmpty()) {
            Node r = q.dequeue();
            visit(r);
            r.visited = true;
            r.visit_time = current_time + 1;
            for (Node n : r.adjacent) {
                if (n.visited == false) {
                    q.enqueue(n);
                }
            }
            r.finished = true;
            r.finish_time = current_time + 1;
        }
    }
    ```
    - O(V+E)

- Depth-First Search (DFS)
    - use case - visit every node
    ```cpp
    void search(Node root, int current_time = 0) {
        if (root == null) {
            return;
        }
        visit(root);
        root.visited = true;
        root.visit_time = current_time + 1;
        for (Node n : root.adjacent) {
            if (n.visited == false) {
                search(n, current_time);
            }
        }
        root.finished = true;
        root.finish_time = current_time + 1;
    }
    ```

- Topologic Ordering
    - ! requires DAG
    - method 1 - reverse order from DFS => when node marked as finished, add as head of linked list
    - method 2 - vertice elimination
    ```c
    Queue order = new Queue()
    Queue processNext = new Queue()
    for (Node n : graph.nodes) {
        for (Node x : n.adjacent) {
            x.inbound++;
        }
    }
    for (Node n : graph.nodes) {
        if (n.inbound == 0) {
            processNext.queue(n)
        }
    }
    while (!processNext.isEmpty()) {
        Node n = processNext.dequeue();
        for (Node x : n.adjacent) {
            x.inbound--
            if (x.inbound == 0) {
                processNext.queue(x)
            }
        }
        order.queue(n)
    }
    ```

- Tarjan
    - identify SCCs (u->v and v->u) (solves 2-SAT)
    - uses back+forward edges for identifying cycles
    - low[u] = min(low[u], low[v]), v is adjacent node

- Kruskal
    - identify MST (minimum spanning tree -> edges than connect all vertices)
    - sort edges by weight
    - check edge
        - if vertices from different sets, then join sets
        - else skip (it's a cycle)
    - O(E lg E)

- Prim
    - keep track of joined nodes in a single tree
    - for remaining neighbour edges
        - if edge links two vertices already in tree
            - skip
        - else
            - add to tree

- Dijkstra
    - shortest paths with non-negative edges
    - maintain priority queue (e.g. min-heap) with nodes to visit - impl. TreeSet
        - [!] use unique id instead of edge value for TreeSet `compareTo()`
    - impl.
        ```
        add nodes to priority queue
        while priority queue is not empty
            node n = queue.pollFirst() // extractMin
            update neighbours
                if (d + edge value < d of neighbour) {
                    d of neighbour = d + edge value // relax
                    if (neighbour in queue) {
                        queue.remove(neighbour)
                        queue.add(neighbour) // decreaseKey
                    }
                    predecessor of neighbour = n
                }
        ```
    - O((V+E) lg V)
    - https://stackoverflow.com/questions/6267172/which-datatype-to-use-as-queue-in-dijkstras-algorithm
    - https://www.baeldung.com/java-dijkstra
        - https://github.com/eugenp/tutorials/tree/master/algorithms-miscellaneous-2/src/main/java/com/baeldung/algorithms/ga/dijkstra

- Bellman-Ford
    - reports negative cycles
    - define relaxation order (aka approximation with min comparisons)
    - after relaxing edges
    - impl.
        ```
        for each edge
            if d[u] + w < d[v] then ERROR
        ```
    - O(VE)

- Floyd-Warshall
    - find shortest paths for all-pairs
    - impl.
        ```
        for each edge (u,v)
           dist[u][v] ← w(u,v)
           next[u][v] ← v
        for k from 1 to |V|
           for i from 1 to |V|
              for j from 1 to |V|
                 if dist[i][j] > dist[i][k] + dist[k][j] then
                    dist[i][j] ← dist[i][k] + dist[k][j]
                    next[i][j] ← next[i][k]
        ```

- Johnson
    - use bellman-ford to reweight graph with no negative edges
        - shortest path edges = 0
        - other edges = 1
    - use dijkstra to find path from each node

- https://hackernoon.com/shortest-and-longest-path-algorithms-job-interview-cheatsheet-2adc8e18869

# String Matching

- Finite-Automata

- Knuth-Morris-Pratt
    - for each index of pattern
        - value = largest length of prefix which is suffix of substring

# Data Structures

- https://g1thubhub.github.io/data-structure-zoo.html
- https://www.interviewcake.com/data-structures-reference

# Dynamic Programming

- https://en.wikipedia.org/wiki/Simplex_algorithm

- https://en.wikipedia.org/wiki/Bellman%E2%80%93Ford_algorithm
- https://en.wikipedia.org/wiki/A*_search_algorithm
- https://en.wikipedia.org/wiki/Approximate_string_matching
- https://en.wikipedia.org/wiki/Viterbi_algorithm
- https://en.wikipedia.org/wiki/Earley_parser
- https://en.wikipedia.org/wiki/Dynamic_time_warping
- https://en.wikipedia.org/wiki/Schreier%E2%80%93Sims_algorithm

- https://florian.github.io/diffing/

# bit manipulation, bit twiddling

```python
hex(0xabcdef >> 8 && 0xff)  # 0xcd
hex(0xabcd >> 8)  # 0xab
hex(0xff << 8)  # 0xff00
```

- [bithacks](https://graphics.stanford.edu/~seander/bithacks.html)
- Hacker's Delight

### reverse bits

```python
def bitrev_u8(n):
    return int(f"{n:08b}"[::-1], 2)

lut = [bitrev_u8(n) for n in range(256)]
def bitrev_u8_fast(n):
    return lut[n]
```

# xor

- [That XOR Trick](https://florian.github.io/xor-trick/)
- [All About XOR](https://accu.org/journals/overload/20/109/lewin_1915/)

- reduce storage requirements
    - e.g. [encoded prev and next in one address](https://en.wikipedia.org/wiki/XOR_linked_list)

# concurrency

- [Java thread-safe collections](./java.md#thread-safe-collections)

- patterns
    - avoid concurrency: logic1 > async > logic2 (e.g. onMessage)
        - before test: logic1 > fake; after test: fake > logic2
        - xunitpatterns humble object (i.e. avoid sleeps due to expensive boilerplate we don't want to test)
    - run in single thread
        - assert async operation didn't run: turn into sync using ThreadScheduler that runs task immediately instead of spawning a new thread
            - java: `MoreExecutors.directExecutor()`
            - https://github.com/dhelper/ConcurrentUnitTesting/blob/master/TestForAsync/AsyncVerifyTests.cs
        - mock object called by thread to fire event immediately
            - https://www.typemock.com/docs/?book=Isolator&page=Documentation%2FHtmlDocs%2Ffiringevents.htm
    - synchronize test
        - signaled pattern: mock object to trigger latch, test awaits on latch
        - busy assert (a.k.a. await with retries)
        - https://github.com/ben-manes/caffeine/blob/1ea398c2f222b39acdc1c4317634a0176494052c/caffeine/src/test/java/com/github/benmanes/caffeine/cache/EvictionTest.java#L205-L236
    - [Dror HELPER: Unit testing patterns for Concurrent code \| UCP2019 \- YouTube](https://www.youtube.com/watch?v=tRe3ddG8O1Y)
        - https://github.com/dhelper/ConcurrentUnitTesting
    - https://www.baeldung.com/java-testing-multithreaded
- maximize thread interleavings
    - run more threads than cpu virtual cores, synchronize logic with CyclicBarrier
        - e.g. Java Concurrency In Practice: 12. Testing Concurrent Programs
    - bruteforce all interleavings
        - https://github.com/google/thread-weaver
        - https://github.com/openjdk/jcstress
        - https://github.com/vmlens/vmlens
    - [Unit testing concurrent code \- YouTube](https://www.youtube.com/watch?v=FvH4RBn2gJ8)
- delays from added logs may decrease reproducability
    - store state in-memory for block under test, then log state after block end
- bad thread started in one test, test passes with thread still running, then thread fails on next test
    - log test name + thread id on thread creation and on failure
    - xref. [The illusion of a call stack \- Why modern systems need a new programming model \- Akka Documentation](https://doc.akka.io/docs/akka/current/typed/guide/actors-motivation.html#the-illusion-of-a-call-stack)

# parsing

```java
// lexer: generate list of tokens
private void scanToken() {
    char c = advance();
    switch (c) {
      case '(': addToken(LEFT_PAREN); break;
      case ')': addToken(RIGHT_PAREN); break;
      case '=': addToken(match('=') ? EQUAL_EQUAL : EQUAL); break;
      case '/':
        if (match('/')) {
          // A comment goes until the end of the line.
          while (peek() != '\n' && !isAtEnd()) advance();
        } else {
          addToken(SLASH);
        }
        break;
        case '"': string(); break;
    }
}
private boolean match(char expected) {
    if (isAtEnd()) return false;
    if (source.charAt(current) != expected) return false;
    current++;
    return true;
}
// parser: consume list of tokens
private Expr unary() {
    if (match(BANG, MINUS)) {
      Token operator = previous();
      Expr right = unary();
      return new Expr.Unary(operator, right);
    }
    return primary();
}
// visitor: traverse AST
interface PastryVisitor {
  void visitBeignet(Beignet beignet);
  void visitCruller(Cruller cruller);
}
class Beignet extends Pastry {
  @Override
  void accept(PastryVisitor visitor) {
    visitor.visitBeignet(this);
  }
}
class AstPrinter implements Expr.Visitor<String> {
  String print(Expr expr) {
    return expr.accept(this);
  }
}
```

- java
    - https://craftinginterpreters.com/contents.html
        - on errors: 6.3.3 Synchronizing a recursive descent parser
- rust
    - https://www.huy.rocks/everyday/05-08-2022-parsing-recursive-descent-parser
    - https://matklad.github.io/2020/04/13/simple-but-powerful-pratt-parsing.html
    - https://github.com/sqlparser-rs/sqlparser-rs
- precedence
    - https://www.engr.mun.ca/~theo/Misc/exp_parsing.htm

# caching

- avoid recomputation on repeated cache misses: subsequent requests wait for already running computation
    - https://google.github.io/guava/releases/19.0/api/docs/com/google/common/cache/CacheBuilder.html
- use value types vs. reference types: looping over references to data may result in more cache misses
    - [Inline Thinking \| Patricia Aas \- Programmer](https://patricia.no/2020/01/16/inline_thinking_in_java.html)
    - [Cache-Oblivious Algorithms and Data Structures](https://cs.au.dk/~gerth/MassiveData02/notes/demaine.pdf)
- [Jach \- Caches are evil](https://www.thejach.com/view/2017/6/caches_are_evil)
- validation (L1/L2 cache misses, branch mispredictions): `perf stat -d -- ./foo`, `cachegrind`

# jit

1. mmap / new / malloc (mprotect)
2. generate native code
3. c cast / reinterpret_cast
4. call (trampoline)
    - e.g. https://chromium.googlesource.com/external/WebKit_trimmed/+/3b62889d46d3fa3b09e261026068121ac190aa61/Source/JavaScriptCore/jit/JITStubs.cpp#91

- register allocation: linear scan / graph coloring
- type inference: avoid time on typeof() and converting values for numeric operations
- tagged pointer: avoid time on sizeof() for structs that represent e.g. small integers
    - e.g. https://github.com/WebKit/WebKit/blob/a6d202ce15959aa453db000ed31e4be5130e7065/Source/JavaScriptCore/runtime/JSCJSValue.h#L395
    - [Small objects and pointer tagging \| Max Bernstein](https://bernsteinbear.com/blog/small-objects/)

- https://en.wikipedia.org/wiki/Profile-guided_optimization

# zero-copy

- serialization
    - https://rkyv.org/zero-copy-deserialization.html
    - https://capnproto.org/encoding.html
- pipes
    - https://mazzo.li/posts/fast-pipes.html
- syscalls
    - https://wjwh.eu/posts/2021-10-01-no-syscall-server-iouring.html

# zero-allocation

- hash tables with fixed number of buckets + open addressing a.k.a. closed hashing
    - validation: pprof callgraph

# Vectorization (SIMD)

- https://www.tinybird.co/blog-posts/simd

# Big-O

Runtime execution proportional to a given input size

```
O(f) = { g ∣ g(n) <= M*f(n) for some M > 0 for large n}
```

- ~/code/doc/algorithms/big-o-cheatsheet.pdf
- [Big\-O Misconceptions &ndash; Søren Sandmann Pedersen](http://ssp.impulsetrain.com/big-o.html)

### common functions

- O(1) - Determining if a number is even or odd; using a constant-size lookup table or hash table
- O(log(n)) - Finding an item in a sorted array with a binary search
- O(n) - Finding an item in an unsorted list; adding two n-digit numbers
- O(n^2) - Multiplying two n-digit numbers by a simple algorithm; adding two n×n matrices; bubble sort or insertion sort
- O(n^3) - Multiplying two n×n matrices by simple algorithm
- O(c^n) - Finding the (exact) solution to the traveling salesman problem using dynamic programming; determining if two logical statements are equivalent using brute force
- O(n!) - Solving the traveling salesman problem via brute-force search

```python
def nlogn(n):
    for i in range(n):
        j = 1
        while j < n:
            j += j

def logsq(n):
    i = 1
    s = 0
    while i <= n:
        j = 1
        while j <= i:
            j = 2 * j
            s += 1
        i = 2 * i
    return s
    # Should be O(log(n)**2)
```

- https://en.wikipedia.org/wiki/Big_O_notation#Orders_of_common_functions
- https://github.com/Mortal/complexity/blob/master/ex.py

### optimizations

- O(n^2)
    ```c
    for (i = 1; i <= length(str); i++) {
        // ...
    }
    ```
- O(n)
    ```c
    int n = length(str);
    for (i = 1; i <= n; i++) {
        // ...
    }
    ```

```
3n^2 − 100n + 6 = O(n^2), because I choose c = 3 and 3n^2 > 3n^2 − 100n + 6;
3n^2 − 100n + 6 = O(n^3), because I choose c = 1 and n^3 > 3n^2 − 100n + 6 when n > 3;
3n^2 − 100n + 6 != O(n), because for any c I choose c × n < 3n^2 when n > c;

O(f(n)) + O(g(n)) → O(max(f(n),g(n)))
```

- https://mohalgorithmsorbit.blogspot.com/

### closed forms

- arithmetic progressions
    ```
    Sum(from: i=1, to: n, body: 1) = n

    Sum(from: i=1, to: n, body: i) =
    Sum(from: i=1, to: n/2, body: (i+(n-i+1))) =
    n(n+1)/2

    S(n, p) = Sum(from: i, to: n, body: i^p) = Theta(n^(p+1))
    ```
- geometric progressions
    ```
    G(n, p) = Sum(from: i=0, to: n, body: p^i) = p(p^(n+1)-1)/(p-1)
    ```
- other
    - permutations
    - combinations
    ```
    Sum(from: i=0, to: n, body: 2^i) = 2^(n+1) - 1

    log_b(k) = c <=> b^c = k
    =>
    log_10(p) = log_2(p)/log_2(10)
    ```

# case studies

- improving compression by sorting data
    - [The sort \-\-key Trick · Gwern\.net](https://www.gwern.net/Sort)
        ```bash
        # Sort by first subdirectory (if there’s a bunch of foo.com/wp-content/* & bar.com/wp-content/* files, then the /wp-content/ files will all sort together regardless of “f” and “b” being far from each other; similarly for domain.com/images/, domain.com/css/ etc):
        cd ~/www/ && find . -type f -print0 \
            | sort --zero-terminated --key=3 --field-separator="/" \
            | tar c --to-stdout --no-recursion --null --files-from - \
            | xz -9 --stdout \
            | wc --bytes
        # 23897682908
        ## 0.2763×
        ```
- efficient weighted graph traversal
    - https://github.com/Pusty/writeups/tree/master/pbctf2021#binary-tree
- API references with time complexity
    - https://redis.io/commands/
- Implicit type checking uses too much memory
    - https://news.ycombinator.com/item?id=26340517
- Parameter values require implicit type casting but also invalidate database index
    - https://news.ycombinator.com/item?id=26338468
- runtime hash-table creation and lookup slower than binary search, due to amortized cost of malloc+free
    - https://phasetw0.com/windows-internals/optimizing_function_resolving/
- Iteration order of hash tables
    - [How malloc broke Serenity&\#39;s JPGLoader, or: how to win the lottery \- sin\-ack&\#39;s writings](https://sin-ack.github.io/posts/jpg-loader-bork/)
        - [LibGfx: Make JPGLoader iterate components deterministically · SerenityOS/serenity@a10ad24 · GitHub](https://github.com/SerenityOS/Serenity/commit/a10ad24c760bfe713f1493e49dff7da16d14bf39)
    - https://news.ycombinator.com/item?id=27377867
        > To add to this, libraries aren't consistent about convention either. Take the common "RGBA". Is this describing the byte order? Or describing most-significant to least-significant 0xRRGGBBAA, which might be little-endian encoded into a "ABGR" byte order? If you think that's stupid idea and that I'm an idiot for suggesting it, what about 16-bit RGB formats where the G component straddles both bytes? Okay, so those aren't so common anymore - but what about DXT/BC compressed formats which encode 4x4 pixel chunks at a time, and don't cleanly decompose into "channels" in the first place?
        > D3DFMT_A8R8G8B8 (Direct3D 9) is equivalent to DXGI_FORMAT_B8G8R8A8_UNORM (DXGI / Direct3D 10+). Note that one enumeration lists the components in reverse order of the other, and that this is correct! https://docs.microsoft.com/en-us/windows/win32/direct3d10/d3... .
        > Documentation often completely omits information endian or encoding - and when it doesn't, it's often hidden away where you'll never find it, and usually assumes x86/x64/little-endian processors. The behavior on big-endian machines is best found out through testing - even if the documentation is clear, the documentation stands a good chances of lying, and CI probably doesn't test on big-endian meaning bugs have likely arisen, and there's a good chance your copy of the library is old and doesn't contain any bugfixes.
        > In light of all of the above, RGB vs BGR confusion is one of the most natural points of confusion to run across when dealing with image formats. "Just use the type system!" ignores where these bugs crop up - (de)serialization, converting streams of bytes to types or vicea versa. Someone must write the code, declaration, whatever - and the type system has no means of ensuring that correctly matches whatever not-computer-readable spec that the (de)serialization is supposed to match - and so it will, frequently, be understandably incorrect.
- ring buffer wraparound
    - http://doc.9gridchan.org/blog/161214.hubfsdebug
        > Periodically, the client I was not actively using would stop receiving messages, although it could still send data successfully.
        > Hubfs uses ring-buffer type data structures, and the logic for handling "wrap around" is tricky. The bug is occurring when multiple readers' requests are stored at the maximum end of the queue, wraparound happens, and then their requests are forgotten.
    - http://doc.9gridchan.org/blog/161216.hubfsbugfix
        > Rather than having complex logic changing the pattern the mail carrier walks, it was much simpler to "change the numbers on the boxes" and copy the pointers from the end of the message queue to the beginning. That way, no extra variables or variant message-answering loops were needed.
    - what if there's double wraparound? won't k messages in the 2nd wraparound overwrite the first k messages in the 1st wraparound?
