# Vanilla

- https://tobiasahlin.com/blog/move-from-jquery-to-vanilla-javascript/#document-ready
    - ~/Downloads/moving-from-jquery-to-vanilla-js.md
- https://gist.github.com/thegitfather/9c9f1a927cd57df14a59c268f118ce86#add-elements-to-the-dom-cont
    - ~/Downloads/vanilla-js-cheatsheet.md

# Debugging

```bash
node inspect app.js
# Input:
# repl
```

```javascript
debugger;

let user = null;
console.log({user});
console.log(arguments[0]);
console.table(["apples", "oranges", "bananas"]);

console.trace();
console.log(new Error().stack);

eval('console.log((function() { return !this; })());')
eval('"use strict"; console.log((function() { return !this; })());')
```

https://developer.mozilla.org/en-US/docs/Web/API/Console/count

```bash
env \
    DEBUG='*' \
    NODE_DEBUG='*' \
    node -e 'console.log(2+2)'

# syntax check
node --check ./index.js

node --stack-trace-limit=100 ./index.js

node --cpu-prof --heap-prof -e "require('request')"
# On browser: F12 > Memory > Load profile...
# On browser: F12 > Performance > Load profile...
# -- https://electronjs.org/docs/tutorial/performance

NODE_OPTIONS="--perf-basic-prof --perf-prof-unwinding-info" npm run
artillery quick -r 200 -d 0 http://localhost:3000
sudo perf record -F 99 -g -p $NODEJS_APP_PID -- sleep 60
sudo perf script -f --header > stacks.test.$(date --iso-8601)
# -- https://medium.com/yld-blog/cpu-and-i-o-performance-diagnostics-in-node-js-c85ea71738eb

# --trace-sync-io
#     Print a stack trace whenever synchronous I/O is detected after the first turn of the event loop.
# --zero-fill-buffers
#     Automatically zero-fills all newly allocated Buffer and SlowBuffer instances.
```

# Tracing

```javascript
handler = {
   apply: function(target, thisArg, argumentsList) {
   }
}
window.open = new Proxy(window.open, handler);
Element.prototype.appendChild = new Proxy(Element.prototype.appendChild, handler);
```

### DevTools

```bash
# debug and run script
node --inspect app.js
# debug and break before running script
node --inspect-brk app.js
# => chrome://inspect/#devices > Open dedicated Devtools for Node
# -- https://marmelab.com/blog/2018/04/03/how-to-track-and-fix-memory-leak-with-nodejs.html

# ||
npm install -g ndb
ndb node app.js
```

https://nodejs.org/en/docs/guides/debugging-getting-started/
https://nodejs.org/en/docs/inspector
https://github.com/GoogleChromeLabs/ndb
https://github.com/11ways/janeway

conditional breakpoint on func call
    debug(postMessage, 'arguments[1] == "*"')
log dom events for object
    monitorEvents(window, 'message')
modify dom response from requests
    overrides > enable local overrides
network tab - file dependencies
    ctrl-click JS and DOC
    shift-select file - other are highlighted
memory tab > heap snapshot - strings in memory
    retainers > object
    :) strings already concatenated / evaled, could be missed when searching source code
https://www.youtube.com/watch?v=Y1S5s3FmFsI

### V8

https://eternalsakura13.com/2018/08/02/v8_debug/

# Linting

```bash
# Output: package.json
npm init
# Output: .eslintrc.js
npm install eslint --save-dev
./node_modules/.bin/eslint --init
# ||
npm install typescript
```

https://eslint.org/docs/user-guide/configuring

# Linking

### Enable

```bash
cd some-dep
# Output: symlink at global modules dir, target is local `some-dep` dir
npm link

cd my-app
# Output: symlink at `my-app` modules dir, target is global `some-dep` dir
npm link some-dep
```

### Disable

```bash
cd my-app
npm uninstall --no-save some-dep && npm install 

cd some-dep
npm uninstall
```

### Enabling breakpoints on `some-dep`

On `launch.json`:

```json
"runtimeArgs": [
  "--preserve-symlinks"
]
```

https://medium.com/dailyjs/how-to-use-npm-link-7375b6219557

### Globals

```json
"env": {
    "node": true,
    "commonjs": true,
    "browser": true,
    "es6": true
}
```

```json
"globals": {
    "process": true
}
```

https://stackoverflow.com/questions/50894000/eslint-process-is-not-defined

# Benchmarking

https://localvoid.github.io/uibench/
https://github.com/krausest/js-framework-benchmark

# WebSocket

https://github.com/websockets/ws/issues/353

# Virtual DOM, diff patch trees

https://github.com/Matt-Esch/virtual-dom
https://reactjs.org/docs/reconciliation.html
https://programming.vip/docs/realization-and-analysis-of-virtual-dom-diff-algorithm.html
[React in 33 lines | Hacker News](https://news.ycombinator.com/item?id=22776753)

# Frameworks

~/code/src/web/todomvc/examples/vanilla-es6/
~/code/src/web/todomvc/examples/vanillajs
    http://todomvc.com/examples/vanillajs/#/

https://stackoverflow.com/questions/34700438/global-events-in-angular

# Selectors

```javascript
document.querySelectorAll('iframe').forEach( item =>
    console.log(item.contentWindow.document.body.querySelectorAll('a'))
)

setTimeout(() => Array.prototype.filter.call(document.querySelectorAll('a'), e => {return /evening/.test(e.textContent);})[0].click(), 2000)
```

# Introspection

Function.prototype.toString

```javascript
o=window; do Object.getOwnPropertyNames(o).forEach(name => {console.log(name, o[name]);}); while(o = Object.getPrototypeOf(o));
```

# Overriding

https://stackoverflow.com/questions/9267157/why-is-it-impossible-to-change-constructor-function-from-prototype

# Generated code

```bash
node --print-opt-code
```

# Cross-Origin script errors

https://insert-script.blogspot.com/2019/07/errorpreparestacktrace-allows-to-catch.html
https://portswigger.net/blog/json-hijacking-for-the-modern-web

# Packages - Deduplication, Version Pinning

```bash
npm ls
yarn why

npm shrinkwrap
```

https://docs.npmjs.com/files/package-locks
https://yarnpkg.com/lang/en/docs/selective-version-resolutions/

# Packages - Updating version

```bash
vim package.json
rm package-lock.json
npm install
```

# execute

```bash
npx some-package
# ~=
npm install some-package
./node_modules/.bin/some-package
```

# Promises

```javascript
// https://github.com/petkaantonov/bluebird
Promise.longStackTraces();

// || manual
Promise.resolve()
    .then(outer)
    .then(inner)
    .then(evenMoreInner())
    .catch(function (err) {
            console.log(err.message);
            console.log(err.stack);
        });
```

# Deobfuscation

http://blog.kotowicz.net/2010/04/beating-javascript-obfuscators-with.html

examples
    https://gist.github.com/myuen-tw/9c196f8daa6cbedf95a3e77bdcec9651

```javascript
// Running:
// - VM or sandbox - e.g. https://repl.it

var _original_unescape = window.unescape;
window.unescape = function() {
    var u = _original_unescape.apply(this, arguments); // this calls the _original_ function
    console.log('unescape ', arguments, u);
    return u;
}

var _original_fromCharCode = String.fromCharCode;
String.fromCharCode = function() {
    var u = _original_fromCharCode.apply(this, arguments);
    console.log('fromcharcode ', arguments, u);
    return u;
}

var _original_eval = window.eval;
window.eval = function() {
    var args = arguments;
    console.log('eval ', arguments, u);
    var u = _original_eval.apply(this, arguments);
    debugger;
    return u;
}
```

[JS NICE: Statistical renaming, Type inference and Deobfuscation](http://jsnice.org/)

# Running untrusted code

https://cuckoosandbox.org/
https://www.freecodecamp.org/news/running-untrusted-javascript-as-a-saas-is-hard-this-is-how-i-tamed-the-demons-973870f76e1c/
    https://github.com/apocas/dockerode
    https://github.com/puppeteer/puppeteer/blob/master/docs/troubleshooting.md#running-puppeteer-in-docker
    https://github.com/patriksimek/vm2
https://medium.com/@devnullnor/a-secure-node-sandbox-f23b9fc9f2b0
    https://github.com/asvd/jailed
    https://gvisor.dev/
        https://github.com/google/gvisor/issues/115
https://gist.github.com/pfrazee/8949363
    https://www.owasp.org/index.php/HTML5_Security_Cheat_Sheet#Web_Workers
    http://www.w3.org/TR/CSP11/#processing-model
    https://github.com/martindrapeau/csvjson-app/blob/master/js/src/sandbox.js

# webpack

DevTools > Settings > Preferences > Sources > Check: Enable JavaScript source maps
DevTools > Sources > Page > webpack://

https://www.mikeglopez.com/source-mapping-webpack-for-chrome/

# typescript

https://www.typescriptlang.org/play/index.html

# observers

[IntersectionObserver](https://developer.mozilla.org/en-US/docs/Web/API/MutationObserver) - monitored object has DOM tree changes
[IntersectionObserver](https://developer.mozilla.org/en-US/docs/Web/API/Intersection_Observer_API) - monitored object enters or exits another element or viewport

# csp w/ 3rd party scripts

<% response.setHeader("Content-Security-Policy", "style-src 'unsafe-inline' 'self' https://cdn.cookielaw.org; frame-ancestors 'self'; default-src 'unsafe-inline' 'self' data: https://cdn.cookielaw.org https://code.jquery.com https://geolocation.onetrust.com;"); %>

# heap

```bash
node --max-old-space-size=4096
```

# tasks

```bash
grunt --verbose --debug
grunt --gruntfile app/templates/Gruntfile.js --base .
```

### loading resources

- Network Throttling = Enabled
- Online > speed = Fast 3G

=> app waits for network request to complete despite not needing resource

https://developer.mozilla.org/en-US/docs/Web/API/Service_Worker_API

### cpu profiling

https://developer.mozilla.org/en-US/docs/Web/API/Web_Workers_API/Using_web_workers

https://github.com/node-inspector/v8-profiler

### memory profiling

```bash
node --track-heap-objects

node --expose-gc
# On browser: F12 > gc()

node --v8-options | grep -i 'expose\|prof'
```

https://github.com/bretcope/node-gc-profiler
    https://www.dynatrace.com/news/blog/understanding-garbage-collection-and-hunting-memory-leaks-in-node-js/

# case studies

https://stackoverflow.com/questions/38637003/what-s-happening-in-this-code-with-number-objects-holding-properties-and-increme#38637228
