#!/usr/bin/env python3

# Usage:
# printf '%s\n%s' '#!/bin/sh' 'printf "%s" "$(~/bin/graph2tree.py | sed '"'"'s/$/\//g'"'"')"' > ~/bin/vim-tree-wrapper/tree
# env PATH=$HOME/bin/vim-tree-wrapper:$PATH vim -c 'Tree'

# References:
# ~/.vim/bundle/vim-tree/autoload/tree.vim
# ~/.vim/after/ftdetect/tree.vim

import networkx as nx


def nx_ascii_tree(graph, key=None):
    """
    Creates an printable ascii representation of a directed tree / forest.

    Args:
        graph (nx.DiGraph): each node has at most one parent (
            i.e. graph must be a directed forest)
        key (str): if specified, uses this node attribute as a label instead of
            the id

    References:
        https://stackoverflow.com/questions/32151776/visualize-tree-in-bash-like-the-output-of-unix-tree

    Example:
        >>> import networkx as nx
        >>> graph = nx.dfs_tree(nx.balanced_tree(2, 2), 0)
        >>> text = nx_ascii_tree(graph)
        >>> print(text)
        └── 0
           ├── 1
           │  ├── 3
           │  └── 4
           └── 2
              ├── 5
              └── 6
    """
    import six
    import networkx as nx
    branch = '├─'
    pipe = '│'
    end = '└─'
    dash = '─'

    assert nx.is_forest(graph)
    assert nx.is_directed(graph)

    lines = []

    def _draw_tree_nx(graph, node, level, last=False, sup=[]):
        def update(left, i):
            if i < len(left):
                left[i] = '   '
            return left

        initial = ['{}  '.format(pipe)] * level
        parts = six.moves.reduce(update, sup, initial)
        prefix = ''.join(parts)
        if key is None:
            node_label = str(node)
        else:
            node_label = str(graph.nodes[node]['label'])

        suffix = '{} '.format(dash) + node_label
        if last:
            line = prefix + end + suffix
        else:
            line = prefix + branch + suffix
        lines.append(line)

        children = list(graph.succ[node])
        if children:
            level += 1
            for node in children[:-1]:
                _draw_tree_nx(graph, node, level, sup=sup)
            _draw_tree_nx(graph, children[-1], level, True, [level] + sup)

    def draw_tree(graph):
        source_nodes = [n for n in graph.nodes if graph.in_degree[n] == 0]
        if source_nodes:
            level = 0
            for node in source_nodes[:-1]:
                _draw_tree_nx(graph, node, level, last=False, sup=[])
            _draw_tree_nx(graph, source_nodes[-1], level, last=True, sup=[0])

    draw_tree(graph)
    text = '\n'.join(lines)
    return text


graph = nx.dfs_tree(nx.balanced_tree(2, 2), 0)
text = nx_ascii_tree(graph)
print(text)
