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
