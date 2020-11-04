var o = '';
export default function(tree) {
  tree.match({ }, node => {
    o += `${node.tag}\n`;
    return node;
  });
  return o;
}
