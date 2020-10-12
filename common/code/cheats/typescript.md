# +

https://www.typescriptlang.org/play/index.html

# private fields

- After transpilation, find `WeakMap`
    - bypass: `eval('_object.get(field)')`
        ```javascript
        window.eval('_object')
        // ReferenceError: window is not defined
        ```
            - Not available under `node` => use `eval()`
            - If outside `node`:
                ```javascript
                (window as any).eval('_object')
                ```
        ```javascript
        eval('_object')
        // WeakSet { <items unknown> }
        ```
        > there is no list of current objects stored in the collection. `WeakSets` are not enumerable.
            - https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/WeakSet
        - eval != transpiling from string
            - https://stackoverflow.com/questions/45153848/evaluate-typescript-from-string
            - https://github.com/Microsoft/TypeScript-wiki/blob/master/Using-the-Compiler-API.md#a-simple-transform-function
    - [Private named instance fields by mheiber · Pull Request \#30829 · microsoft/TypeScript · GitHub](https://github.com/Microsoft/TypeScript/pull/30829)
        - https://github.com/tc39/proposal-class-fields/blob/master/PRIVATE_SYNTAX_FAQ.md#how-can-you-model-encapsulation-using-weakmaps
- [V8's inspector API](https://chromedevtools.github.io/devtools-protocol/) from [Node.js](https://nodejs.org/api/inspector.html)
    ```javascript
    global.flag = flag;
    const inspector = require('inspector');
    const session = new inspector.Session();
    session.connect();
    session.post('Runtime.evaluate', {expression: 'flag'}, (e, d) => {
      session.post('Runtime.getProperties', {objectId: d.result.objectId}, (e, d) => {
        console.log(d.privateProperties[0].value.value);
      });
    });
    ```
- [Hoisting](https://developer.mozilla.org/en-US/docs/Glossary/Hoisting)
    ```javascript
    const fs = require('fs');
    // require() defined in node, but shadowed
    function require() {
      const fs = process.mainModule.require('fs');
      console.log(fs.readFileSync('flag.txt').toString());
    }
    ```
- https://nodejs.org/api/v8.html#v8_v8_getheapsnapshot
    ```javascript
    const v8 = require('v8');
    const memory = v8.getHeapSnapshot().read();
    const index = memory.indexOf('SEC' + 'CON');
    const len = memory.slice(index).indexOf('}');
    const flagBuffer = memory.slice(index, index + len + 1);
    console.log(flagBuffer.toString());
    ```
