var el = document.querySelector('div.sidebarItem:nth-child(2)');
var treeWalker = document.createTreeWalker(
    el,
    NodeFilter.SHOW_TEXT,
    n => {
        return /script|style/.test(n.tagName) ?
            NodeFilter.FILTER_SKIP :
            NodeFilter.FILTER_ACCEPT;
    },
    false
);

var nodeList = [];
var currentNode = treeWalker.currentNode;
while (currentNode) {
    nodeList.push(currentNode);
    currentNode = treeWalker.nextNode();
}

nodeList.filter(n => {
    return n.nodeType == 3;
}).forEach(n => console.log(n.textContent));
