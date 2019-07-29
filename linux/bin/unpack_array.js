var fs = require('fs'),
    esprima = require('esprima');

function traverse(node, func, branch) {
    branch = branch || [];
    branch.push(node);

    func(node, branch);
    var recursiveTraverse = function(node) {
        traverse(node, func, branch);
    };
    for (var key in node) {
        if (node.hasOwnProperty(key)) {
            var child = node[key];
            if (typeof child === 'object' && child !== null) {
                if (Array.isArray(child)) {
                    child.forEach(recursiveTraverse);
                } else {
                    traverse(child, func, branch);
                }
            }
        }
    }

    branch.pop();
}

function analyzeCode(code) {
    var ast = esprima.parse(code);
    var arrayStats = {};
    var functionsStats = {};
    var addEntry = function(dict, funcName) {
        if (!dict[funcName]) {
            dict[funcName] = {
                calls: 0,
                callerFunctions: [],
                declarations: 0,
                elements: []
            };
        }
    };

    traverse(ast, function(node, branch) {
        if (node.type === 'AssignmentExpression' &&
                node.right.type === 'ArrayExpression') {
            addEntry(arrayStats, node.left.name);
            arrayStats[node.left.name].declarations++;
            arrayStats[node.left.name].elements = node.right.elements.map(function(el) {
                // TODO: Deal with identifiers, track and lookup by 'name'
                return el.type === 'Literal' ? el.raw : el;
            });
        } else if (node.type === 'VariableDeclarator' &&
                node.init &&
                node.init.type === 'ArrayExpression' &&
                node.init.elements &&
                node.init.elements.length > 0) {
            addEntry(arrayStats, node.id.name);
            arrayStats[node.id.name].declarations++;
            arrayStats[node.id.name].elements = node.init.elements.map(function(el) {
                // TODO: Deal with identifiers, track and lookup by 'name'
                return el.type === 'Literal' ? el.raw : el;
            });
        } else if (node.type === 'MemberExpression' &&
                node.object &&
                node.object.type === 'Identifier') {
            addEntry(arrayStats, node.object.name);
            arrayStats[node.object.name].calls++;
            for (var i = branch.length - 1; i >= 0; i--) {
                if (branch[i].type === 'VariableDeclarator' &&
                        branch[i].id.type === 'Identifier' &&
                        branch[i].init &&
                        branch[i].init.type === 'FunctionExpression') {
                    arrayStats[node.object.name].callerFunctions.push(branch[i].id.name);
                }
            }
            //console.log(branch);
        } else if (node.type === 'FunctionDeclaration') {
            addEntry(functionsStats, node.id.name);
            functionsStats[node.id.name].declarations++;
        } else if (node.type === 'CallExpression' && 
                node.callee.type === 'Identifier') {
            addEntry(functionsStats, node.callee.name);
            functionsStats[node.callee.name].calls++;
        }
    });

    processResults(arrayStats);
}

function processResults(results) {
    var largestElementCount = 0;
    var packedArrayName = '';
    var packedArrayCaller = '';
    var packedArrayElements = [];
    for (var name in results) {
        if (!(results.hasOwnProperty(name))) {
            continue;
        }
        var stats = results[name];
        if (!(stats.elements.length > 0 && stats.calls > 0)) {
            continue;
        }
        console.log('// Array:', name, 
            ', with elements:', stats.elements.length, 
            ', called:', stats.calls,
            ', by:', stats.callerFunctions.join(', '));

        // TODO: Support multiple caller functions.
        if (stats.elements.length >= largestElementCount) {
            largestElementCount = stats.elements.length;
            packedArrayName = name;
            packedArrayCaller = stats.callerFunctions[0];
            packedArrayElements = stats.elements;
        }
    }
    console.log('// Packed array:', packedArrayName);

    // TODO: eval functions, instrument calls with array lookup result
    // See: https://github.com/substack/static-eval/blob/master/index.js
    // See: https://esprima.readthedocs.io/en/latest/syntactic-analysis.html
    (function(_0xb98c1f, _0x3da341) {
        var _0x41b452 = function(_0x5108ed) {
            while (--_0x5108ed) {
                _0xb98c1f.push(_0xb98c1f.shift());
            }
        };
        _0x41b452(++_0x3da341);
    }(packedArrayElements, 0x1a3));
    for (var i = 0; i < packedArrayElements.length; i++) {
        var packedCall = (packedArrayCaller + 
            '(\'0x' + (i).toString(16) + '\')').replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
        code = code.replace(new RegExp(packedCall, 'g'), packedArrayElements[i]);
    }
    console.log(code);
}

if (process.argv.length < 3) {
    console.log('Usage:', process.argv[0], process.argv[1], 'file.js');
    process.exit(1);
}

var filename = process.argv[2];
var code = fs.readFileSync(filename, 'utf-8');
analyzeCode(code);
