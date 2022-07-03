const {
  RefactorSession
} = require('shift-refactor');
const {
  parseScript
} = require('shift-parser');
const fs = require('fs');

const fileContents = fs.readFileSync('./source.js', 'utf8');
const tree = parseScript(fileContents);
const refactor = new RefactorSession(tree);
refactor.rename('IdentifierExpression[name="oldName"]', 'newName');
refactor.insertBefore(
  `ExpressionStatement[expression.type="CallExpression"]`,
  node => `console.log("Calling ${node.expression.callee.name}()")`
);
console.log(refactor.print());
