# Big-O

Runtime execution proportional to a given input size

```
O(f) = { g ∣ g(n) <= M*f(n) for some M > 0 for large n}
```

# Sorts

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

Selection Sort
    go through array, updating minimum
    switch minimum with last ordered index+1

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

```
S(n) = Sum(from: i=0, to: n-1, body:
    Sum(from: j=i+1, to: n-1, body: 1)
) =
Sum(from: i=0, to: n-1, body: n-i-1) =
n(n-1)/2

S(n) <= n(n-1) = O(n^2)
S(n) >= (n/2)(n/2) = Omega(n^2)
```

Insertion Sort
    compare current index with last ordered index
        if smaller
            switch
                then current index + 1
        else
            last ordered index - 1 until beginning
                then current index + 1

Bubble Sort
    pairwise compare indexes
        switch if smaller is last index
    last element will be ordered
        then loop for length - 1
    => use bool for swapped (stop condition)
    :) Good for seeing already sorted

Merge Sort
    Subdivide list
        Merge each sub list
            copy both sub lists into helper array
            compare one index from each sub list
                if index of sub list -lt other index, then assign to original array
    :) Good for single linked lists (only +1 extra space)
    :) Access contiguous memory locations
    :) Parallelization

Heap Sort
    heapify => ensuring child is smaller than parent
    Extract maximum from heap
        Redo heapify

Quick Sort
    Choose last element as pivot
        Check i=0 and j=pivot-1
            if i > pivot then
                j = pivot
                pivot-old = i
                i = j
            else
                j = pivot
                pivot-old = j
                i = j
        i++
        j--
    Subdivide into two lists
        0 until pivot
        pivot+1 until end

Counting sort
    index array (length = largest value) -> store counts of each index
    loop index array -> pos i+1 = value i + value i+1
    output array -> loop initial array from end
        i value -> lookup index array = i value
            output-index = value-1 in index-array
            output-value = index in index-array
    :) eliminate duplicates

Radix sort
    :) O(kn) can be better than O(n log(n)), n = count_elements, k = count_passes

### Binary Search

```java
Collections.sort(list, Collections.reverseOrder());
// Output: [E, D, C, B, A]

int index = Collections.binarySearch(list, "D", Collections.reverseOrder());
// Output: 1
```

# Trees

binary tree - each node has up to 2 children
binary search tree - ordered
    ```
    foreach node n, left_descedents <= n < right_descendents
    ```
    ? duplicates cases: unsupported, left ordered or right ordered
complete binary tree - each level is filled, with optional rightmost children in last level missing
full binary tree - each node has 0 or 2 children
perfect binary tree - full and complete

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

### binary heaps

min-heap - each node is smaller than children
max-heap - each node is larger than children
```java
public class MaxComparator implements Comparator<Integer> {
    public int compare( Integer x, Integer y ) {
        return y - x;
    }
}
PriorityQueue maxHeap = new PriorityQueue(size, new MaxComparator());
```

insert()
    at rightmost position, ensuring complete tree property
    swap new node with parent, until ensuring min-heap property
    O(log n)
extract_minimum()
    remove root node
    move bottommost rightmost node to root
    swap new root node with smallest child, until ensuring min-heap property
    O(log n)

https://www.geeksforgeeks.org/min-heap-in-java/

### trie

stores words where shared prefixes share same parents
find()
    O(k), k = length of prefix

### balanced trees

ensures O(log n) runtime for insert() and find()
    ! left and right subtrees could have diff sizes

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
https://www.programcreek.com/2013/02/leetcode-balanced-binary-tree-java/

AVL
    diff height between children -lt 2

B-tree
    structure fully in memory
    :) performant caching

Red-Black

# Graphs

storing
    adjacency matrix - read order = row-column
    adjacency list ~= hash table where hash() = node id

marking
    white = un-visited
    grey = visited
    black = finished (no more children to visit)

back edge = points to gray node
forward edge = points to black node

Breadth-First Search (BFS)
    use case - path between two nodes (quicker for less deep paths)
    => bidirectional search (BFS started from both nodes)
        O(k^d) vs. O(2*k^(d/2)), k = count_adjacent_nodes, d = path_length
    ```c
    void search(Node root, int current_time = 0) {
        Queue queue = new Queue();
        queue.enqueue(root);
        while (!queue.isEmpty()) {
            Node r = queue.dequeue();
            visit(r);
            r.visited = true;
            r.visit_time = current_time + 1;
            for (Node n : r.adjacent) {
                if (n.visited == false) {
                    queue.enqueue(n);
                }
            }
            r.finished = true;
            r.finish_time = current_time + 1;
        }
    }
    ```
    O(V+E)

Depth-First Search (DFS)
    use case - visit every node
    ```c
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

Topologic Ordering
    ! requires DAG
    method 1 - reverse order from DFS => when node marked as finished, add as head of linked list
    method 2 - vertice elimination
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

Tarjan
    identify SCCs (u->v and v->u) (solves 2-SAT)
    uses back+forward edges for identifying cycles
    low[u] = min(low[u], low[v]), v is adjacent node

Kruskal
    identify MST (minimum spanning tree -> edges than connect all vertices)
    sort edges by weight
    check edge
        if vertices from different sets, then join sets
        else skip (it's a cycle)
    O(E lg E)

Prim
    keep track of joined nodes in a single tree
    for remaining neighbour edges
        if edge links two vertices already in tree
            skip
        else
            add to tree

Dijkstra
    shortest paths with non-negative edges
    maintain priority queue (e.g. min-heap) with nodes to visit - impl. TreeSet
        /!\ use unique id instead of edge value for TreeSet `compareTo()`
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
    O((V+E) lg V)
    https://stackoverflow.com/questions/6267172/which-datatype-to-use-as-queue-in-dijkstras-algorithm
    https://www.baeldung.com/java-dijkstra
        https://github.com/eugenp/tutorials/tree/master/algorithms-miscellaneous-2/src/main/java/com/baeldung/algorithms/ga/dijkstra

Bellman-Ford
    reports negative cycles
    define relaxation order (aka approximation with min comparisons)
    after relaxing edges
    ```
    for each edge
        if d[u] + w < d[v] then ERROR
    ```
    O(VE)

Floyd-Warshall
    find shortest paths for all-pairs
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

Johnson
    use bellman-ford to reweight graph with no negative edges
        shortest path edges = 0
        other edges = 1
    use dijkstra to find path from each node

https://hackernoon.com/shortest-and-longest-path-algorithms-job-interview-cheatsheet-2adc8e18869

# String Matching

Finite-Automata

Knuth-Morris-Pratt
    for each index of pattern
        value = largest length of prefix which is suffix of substring

# Examples

https://github.com/Mortal/complexity/blob/master/ex.py

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

# Data Structures

https://g1thubhub.github.io/data-structure-zoo.html
https://www.interviewcake.com/data-structures-reference

# Dynamic Programming

https://en.wikipedia.org/wiki/Simplex_algorithm

https://en.wikipedia.org/wiki/Bellman%E2%80%93Ford_algorithm
https://en.wikipedia.org/wiki/A*_search_algorithm
https://en.wikipedia.org/wiki/Approximate_string_matching
https://en.wikipedia.org/wiki/Viterbi_algorithm
https://en.wikipedia.org/wiki/Earley_parser
https://en.wikipedia.org/wiki/Dynamic_time_warping
https://en.wikipedia.org/wiki/Schreier%E2%80%93Sims_algorithm

# Examples - Common functions

O(1) - Determining if a number is even or odd; using a constant-size lookup table or hash table

O(log(n)) - Finding an item in a sorted array with a binary search

O(n) - Finding an item in an unsorted list; adding two n-digit numbers

O(n^2) - Multiplying two n-digit numbers by a simple algorithm; adding two n×n matrices; bubble sort or insertion sort

O(n^3) - Multiplying two n×n matrices by simple algorithm

O(c^n) - Finding the (exact) solution to the traveling salesman problem using dynamic programming; determining if two logical statements are equivalent using brute force

O(n!) - Solving the traveling salesman problem via brute-force search

https://en.wikipedia.org/wiki/Big_O_notation#Orders_of_common_functions

# Examples - Optimizations

O(n^2)
```c
for (i = 1; i <= length(str); i++) {
    // ...
}
```

O(n)
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

https://mohalgorithmsorbit.blogspot.com/
skiena

### closed forms

Sum(from: i=1, to: n, body: 1) = n

arithmetic progressions

Sum(from: i=1, to: n, body: i) =
Sum(from: i=1, to: n/2, body: (i+(n-i+1))) =
n(n+1)/2

S(n, p) = Sum(from: i, to: n, body: i^p) = Theta(n^(p+1))

geometric progressions

G(n, p) = Sum(from: i=0, to: n, body: p^i) = p(p^(n+1)-1)/(p-1)

other

```
Sum(from: i=0, to: n, body: 2^i) = 2^(n+1) - 1

log_b(k) = c <=> b^c = k
=>
log_10(p) = log_2(p)/log_2(10)
```

permutations

combinations

# +

https://github.com/VAR-solutions/Algorithms

~/code/doc/algorithms/big-o-cheatsheet.pdf
~/code/doc/algorithms/CLRS-3rd.pdf
~/code/doc/algorithms/CLRS-3rd-Solutions.pdf
~/code/doc/algorithms/TheAlgorithmDesignManual.pdf
http://ssp.impulsetrain.com/big-o.html
https://en.wikipedia.org/wiki/List_of_logarithmic_identities

https://www.baeldung.com/java-collections-complexity

https://news.ycombinator.com/item?id=7953725
    https://en.wikipedia.org/wiki/Cycle_detection#Floyd's_Tortoise_and_Hare

https://en.wikipedia.org/wiki/Karatsuba_algorithm

string processing
    LZW algorithm
    longest common subsequence algorithm
tree graph processing
    post order depth first search
list processing
    group elements in an array into sub arrays of length k
integer processing
    change of radix algorithm (e.g. change a number from base 10 to base 2)


