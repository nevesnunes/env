# +

https://g1thubhub.github.io/data-structure-zoo.html
https://www.interviewcake.com/data-structures-reference

https://en.wikipedia.org/wiki/Simplex_algorithm
dynamic programming
    https://en.wikipedia.org/wiki/Bellman%E2%80%93Ford_algorithm
    https://en.wikipedia.org/wiki/A*_search_algorithm
    https://en.wikipedia.org/wiki/Approximate_string_matching
    https://en.wikipedia.org/wiki/Viterbi_algorithm
    https://en.wikipedia.org/wiki/Earley_parser
    https://en.wikipedia.org/wiki/Dynamic_time_warping
    https://en.wikipedia.org/wiki/Schreier%E2%80%93Sims_algorithm

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
    go through array
    remember minimum
    switch minimum with last ordered index+1

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
            compare one index from each sub list
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

# Binary Trees

link balanceR(link h) 
{ 
  if (h->N < 2) 
    return h; 
  h = partR(h, h->N/2); 
  h->l = balanceR(h->l); 
  h->r = balanceR(h->r); 
  return h; 
} 

AVL
    diff height between children < 2

B-tree
    structure fully in memory
    :) performant caching

# Graphs

BFS
    for gray node
        enqueue neighbors with d=d+1
        black node
        next in queue
    O(V+E)
DFS
    for gray node
        if no more white nodes reachable
            black node
            finish time = current time + 1
        else
            go to next reachable node
            d time = current time + 1
    back edge = points to gray node
    forward edge = points to black node

Topologic Ordering
    reverse order from DFS

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

    maintain heap with remaining nodes
    for node in tree
        update neighbours
            when d + edge value < d of neighbour
            remember predecessor of neighbour
    O((V+E) lg V)

Bellman-Ford
    reports negative cycles

    define relaxation order (aka approximation with min comparisons)
    after relaxing edges
    for each edge
        if d[u] + w < d[v] then ERROR
    O(VE)

DAG
    use topologic order

Floyd-Warshall
    find shortest paths for all-pairs

    for each edge (u,v)
       dist[u][v] ← w(u,v)
       next[u][v] ← v
    for k from 1 to |V|
       for i from 1 to |V|
          for j from 1 to |V|
             if dist[i][j] > dist[i][k] + dist[k][j] then
                dist[i][j] ← dist[i][k] + dist[k][j]
                next[i][j] ← next[i][k]

Johnson
    use bellman-ford to reweight graph with no negative edges
        shortest path edges = 0
        other edges = 1
    use dijkstra to find path from each node

# String Matching

Finite-Automata

Knuth-Morris-Pratt
    for each index of pattern
        value = largest length of prefix which is suffix of substring
