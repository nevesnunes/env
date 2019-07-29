# Debugger

node inspect _
repl

debugger;

---

npm install -g ndb

---


let user = null;
console.log({user});

console.table(["apples", "oranges", "bananas"]);

https://developer.mozilla.org/en-US/docs/Web/API/Console/count

# Frameworks

https://stackoverflow.com/questions/34700438/global-events-in-angular

# Selectors

document.querySelectorAll('iframe').forEach( item =>
    console.log(item.contentWindow.document.body.querySelectorAll('a'))
)

# Introspection

Function.prototype.toString

# Overriding

https://stackoverflow.com/questions/9267157/why-is-it-impossible-to-change-constructor-function-from-prototype

# Generated code

node --print-opt-code

# Cross-Origin script errors

https://insert-script.blogspot.com/2019/07/errorpreparestacktrace-allows-to-catch.html
https://portswigger.net/blog/json-hijacking-for-the-modern-web

# Packages - Deduplication, Version Pinning

npm ls
yarn why

npm shrinkwrap
https://docs.npmjs.com/files/package-locks
https://yarnpkg.com/lang/en/docs/selective-version-resolutions/

# Packages - Updating version

vim package.json
rm package-lock.json
npm install
