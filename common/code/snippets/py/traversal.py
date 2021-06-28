#!/usr/bin/env python3

# Generators
# - [Breadth First and Depth First Search in Python · GitHub](https://gist.github.com/daveweber/99ea4da41f42ac92cdbf)

def bfs(self):
    q = [self]
    while q:
        n = q.pop(0)
        yield n
        for c in n._children:
            q.append(c)


def dfs(self):
    yield self
    for c in self:
        yield from c.depth_first()

# Dequeue
# - [Breadth\-First Search in Python · GitHub](https://gist.github.com/dpapathanasiou/748a14e56c9171671121710d1905c94f)

def bfs (graph, src, tgt):
    """Return the shortest path from the source (src) to the target (tgt) in the graph"""

    if not graph.has_key(src):
        raise AttributeError("The source '%s' is not in the graph" % src)
    if not graph.has_key(tgt):
        raise AttributeError("The target '%s' is not in the graph" % tgt)

    parents = {src: None}
    queue = deque([src])
    while queue:
        node = queue.popleft()
        for neighbor in graph[node]:
            if neighbor not in parents:
                parents[neighbor] = node
                queue.append(neighbor)
                if node == tgt:
                    break

    path = [tgt]
    while parents[tgt] is not None:
        path.insert(0, parents[tgt])
        tgt = parents[tgt]

    return path

# Lists
# - [Breadth First Tree Traversal using Generators in Python \- Stack Overflow](https://stackoverflow.com/questions/50307142/breadth-first-tree-traversal-using-generators-in-python)
#     - FIXME: In BFS you should use collections.dequeue instead of a list for the queue. Python's lists are implemented as vectors so when you queue.pop(0) that's O(V) instead of O(1) so you won't get the O(V + E) run-time like BFS should have. I believe that this would be O(V^2 + E) instead.

def bfs(graph, start):
    visited, queue = set(), [start]
    while queue:
        vertex = queue.pop(0)
        if vertex not in visited:
            visited.add(vertex)
            queue.extend(graph[vertex] - visited)
    return visited


def bfs_paths(graph, start, end):
    queue = [(start, [start])]
    while queue:
        (vertex, path) = queue.pop(0)
        for next in graph[vertex] - set(path):
            if next == end:
                yield path + [next]
            else:
                queue.append((next, path + [next]))


def dfs(graph, start):
    visited, stack = set(), [start]
    while stack:
        vertex = stack.pop()
        if vertex not in visited:
            visited.add(vertex)
            stack.extend(graph[vertex] - visited)
    return visited


def dfs_paths(graph, start, end):
    stack = [(start, [start])]
    while stack:
        (vertex, path) = stack.pop()
        for next in graph[vertex] - set(path):
            if next == end:
                yield path + [next]
            else:
                stack.append((next, path + [next]))
