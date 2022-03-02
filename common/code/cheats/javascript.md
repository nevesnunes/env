# +

- [typescript](./typescript.md)

- https://www.google.com/search?q=site:https://developer.mozilla.org/en-US/docs%20foo
- [WebPageTest \- Website Performance and Optimization Test](https://www.webpagetest.org/)

# Vanilla

- https://tobiasahlin.com/blog/move-from-jquery-to-vanilla-javascript/#document-ready
    - ~/Downloads/moving-from-jquery-to-vanilla-js.md
- https://gist.github.com/thegitfather/9c9f1a927cd57df14a59c268f118ce86#add-elements-to-the-dom-cont
    - ~/Downloads/vanilla-js-cheatsheet.md
- [Vanilla\-todo: A case study on viable techniques for vanilla web development | Hacker News](https://news.ycombinator.com/item?id=24893247)
    - https://github.com/morris/vanilla-todo

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

# AST traversal, transformation

Testing:

- [AST explorer](https://astexplorer.net/)

Parsers:

- [GitHub \- posthtml/posthtml: PostHTML is a tool to transform HTML/XML with JS plugins](https://github.com/posthtml/posthtml)
- https://eslint.org/docs/developer-guide/working-with-rules
- https://eslint.org/docs/developer-guide/selectors
    - [GitHub \- estools/esquery: ECMAScript AST query library\.](https://github.com/estools/esquery)

Case Studies:

- ./wasm.md#optimizing-temporary-variables
- https://nullpt.rs/tackling-javascript-client-side-security-pt-1/
    - ~/code/snippets/js/decode_jscrambler.js

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

# Testing

- Remove / Nullify URL parameters
- Concurrent requests / sessions
    - e.g.  remove element in one window, view same element in another window
- Misalignments when updating dynamic content

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
- https://medium.com/javascript-in-plain-english/i-created-the-exact-same-app-in-react-and-vue-here-are-the-differences-e9a1ae8077fd
- https://hnpwa.com/
- https://github.com/gothinkster/realworld

- https://stackoverflow.com/questions/34700438/global-events-in-angular

# Browser Automation / Headless Browser

- selenium webdriver
- pyppeteer
    - ~/code/guides/ctf/TFNS---writeups/2020-04-12-ByteBanditsCTF/notes-app/sources/mynotes/visit_link.py
- https://htmlunit.sourceforge.io/

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

// Globals
Object.entries(window)
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

# symbols

- Hidden but readable immutable properties, all values are unique

```javascript
Object.getOwnPropertySymbols()
```

https://medium.com/intrinsic/javascript-symbols-but-why-6b02768f4a5c
https://developer.mozilla.org/en-US/docs/Glossary/Symbol

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

- [de4js \| JavaScript Deobfuscator and Unpacker](https://lelinhtinh.github.io/de4js/)
- [JS NICE: Statistical renaming, Type inference and Deobfuscation](http://jsnice.org/)
- [bumperworksonline\.js · GitHub](https://gist.github.com/myuen-tw/9c196f8daa6cbedf95a3e77bdcec9651)
- [Beating JavaScript obfuscators with Firebug](http://blog.kotowicz.net/2010/04/beating-javascript-obfuscators-with.html)

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

### bypass dummy debugger calls

- ~/code/snippets/js/anti-anti-debugger.js
- Log firefox's `EvalKernel()`
    - https://searchfox.org/mozilla-central/source/js/src/builtin/Eval.cpp#224
    - https://nullpt.rs/tackling-javascript-client-side-security-pt-2/
    ```cpp
    #include "mozilla/Logging.h"
    // ...
    static bool EvalKernel(JSContext* cx, HandleValue v, EvalType evalType,
            AbstractFramePtr caller, HandleObject env,
            jsbytecode* pc, MutableHandleValue vp) {
        // ...
        using mozilla::LogLevel;
        static mozilla::LazyLogModule sLogger("example_logger");
        MOZ_LOG(sLogger, LogLevel::Info, ("Eval: %s", JS_EncodeStringToASCII(cx, v.toString()).get()));
        // ...
    }
    ```
- Given integrity checks and debugger calls evaluated in a separate context, then replace firefox's debugger keyword
    - usage
        ```html
        <script>
        window.oldSlice = Array.prototype.slice;
        Array.prototype.slice = function() {
            overriden_debugger;
            window.oldSlice(arguments);
        }
        </script>
        <script src="./foo.js"></script>
        ```
    - e.g. JScrambler
    - https://nullpt.rs/evading-anti-debugging-techniques/
        ```diff
        --- a/js/src/frontend/ReservedWords.h
        +++ b/js/src/frontend/ReservedWords.h
        @@ -20,7 +20,7 @@
           MACRO(catch, catch_, TokenKind::Catch)                \
           MACRO(const, const_, TokenKind::Const)                \
           MACRO(continue, continue_, TokenKind::Continue)       \
        -  MACRO(debugger, debugger, TokenKind::Debugger)        \
        +  MACRO(ticket_debugger, debugger, TokenKind::Debugger) \
           MACRO(default, default_, TokenKind::Default)          \
           MACRO(delete, delete_, TokenKind::Delete)             \
           MACRO(do, do_, TokenKind::Do)                         \
        --- a/js/src/vm/CommonPropertyNames.h
        +++ b/js/src/vm/CommonPropertyNames.h
        @@ -107,7 +107,7 @@
           MACRO_(currencySign, currencySign, "currencySign")  \
           MACRO_(day, day, "day")                             \
           MACRO_(dayPeriod, dayPeriod, "dayPeriod")           \
        -  MACRO_(debugger, debugger, "debugger")              \
        +  MACRO_(ticket_debugger, debugger, "ticket_debugger")\
           MACRO_(decimal, decimal, "decimal")
        ```

# Running untrusted code

- https://urlscan.io/

- https://www.freecodecamp.org/news/running-untrusted-javascript-as-a-saas-is-hard-this-is-how-i-tamed-the-demons-973870f76e1c/
    - https://github.com/apocas/dockerode
    - https://github.com/puppeteer/puppeteer/blob/master/docs/troubleshooting.md#running-puppeteer-in-docker
    - https://github.com/patriksimek/vm2
- https://medium.com/@devnullnor/a-secure-node-sandbox-f23b9fc9f2b0
    - https://github.com/asvd/jailed
    - https://gvisor.dev/
        - [DNS not working in Docker Compose · Issue \#115 · google/gvisor · GitHub](https://github.com/google/gvisor/issues/115)
- [In\-Application Sandboxing with Web Workers · GitHub](https://gist.github.com/pfrazee/8949363)
    - https://www.owasp.org/index.php/HTML5_Security_Cheat_Sheet#Web_Workers
    - http://www.w3.org/TR/CSP11/#processing-model
    - https://github.com/martindrapeau/csvjson-app/blob/master/js/src/sandbox.js

# webpack

DevTools > Settings > Preferences > Sources > Check: Enable JavaScript source maps
DevTools > Sources > Page > webpack://

https://www.mikeglopez.com/source-mapping-webpack-for-chrome/

# observers

[IntersectionObserver](https://developer.mozilla.org/en-US/docs/Web/API/MutationObserver) - monitored object has DOM tree changes
[IntersectionObserver](https://developer.mozilla.org/en-US/docs/Web/API/Intersection_Observer_API) - monitored object enters or exits another element or viewport

# shadow root

```javascript
// Reference: https://github.com/uBlock-user/uBO-Scriptlets/blob/master/scriptlets.js
const queryShadowRootElement = (shadowRootElement, rootElement) => {
    if (!rootElement) {
        return queryShadowRootElement(shadowRootElement, document.documentElement);
    }
    const els = rootElement.querySelectorAll(shadowRootElement);
    for (const el of els) { if (el) {return el;} }
    const probes = rootElement.querySelectorAll('*');
    for (const probe of probes) {
         if (probe.shadowRoot) {
             const shadowElement = queryShadowRootElement(shadowRootElement, probe.shadowRoot);
         if (shadowElement) { return shadowElement; }
         }
    }
    return null;
};
```

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

# Chrome extension source

```bash
extension_id=jifpbeccnghkjeaalbbjmodiffmgedin
curl -L -o "$extension_id.zip" "https://clients2.google.com/service/update2/crx?response=redirect&os=mac&arch=x86-64&nacl_arch=x86-64&prod=chromecrx&prodchannel=stable&prodversion=44.0.2403.130&x=id%3D$extension_id%26uc"
unzip -d "$extension_id-source" "$extension_id.zip"
```

- `chrome://version/ > Profile Path > Extensions`
- [CRX Viewer](https://robwu.nl/crxviewer/)
- [GitHub \- Rob\-\-W/crxviewer: Add\-on / web app to view the source code of Chrome / Firefox / Opera 15 extensions and zip files\.](https://github.com/Rob--W/crxviewer)

# case studies

- https://stackoverflow.com/questions/38637003/what-s-happening-in-this-code-with-number-objects-holding-properties-and-increme#38637228
- https://www.ekioh.com/devblog/google-docs-in-a-clean-room-browser/
    > Pressing some keys inserted one letter, but other keys inserted that letter twice.
- https://github.com/mendix/docs/blob/development/content/howto/monitoring-troubleshooting/detect-and-resolve-performance-issues.md
    - add timings around functions to profile; add indexes for complex queries on DOM tree; avoid complex loops or multiple modifications using batching; avoid multiple network requests by simplifying nested views
