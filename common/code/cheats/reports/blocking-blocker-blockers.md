# blocking-blocker-blockers

a.k.a. circumventing adblocker detection

## UserScript parameters

```javascript
// @run-at document-start
```

## Techniques

### MutationObserver

- Handles dynamic modifications
- Used for non-obfuscated names

```javascript

var remove = function(el) {
    if(/fingerprint/i.test(el.id)) {
        el.parentNode.removeChild(el);
        console.log("[aa521357-eae5-4062-b18a-79a62c261912] Removed elements!");
    }
};
(new MutationObserver(function(mutations, observer) {
    mutations.reduce(function(accumulator, current) {
        return accumulator.concat(Array.prototype.slice.call(
            current.addedNodes));
    }, []).forEach(remove);
})).observe(document, {
    childList: true,
    subtree: true
});

// Also handle modifications done before observing
document.querySelectorAll('fingerprint').forEach(remove);
```

### prototype

- Used for randomly obfuscated names or anonymous functions

```javascript
function main() {
    aa521357_eae5_4062_b18a_79a62c261912_sanitize = function(el) {
        // Obfuscated function names have been eval'd,
        // they can now be read from the call stack
        if (/fingerprint/i.test((new Error()).stack)) {
            // Break execution flow
            throw new Error('[aa521357_eae5_4062_b18a_79a62c261912] sanitize');
        }
    };

    console.log('[aa521357-eae5-4062-b18a-79a62c261912] redefining functions');
    aa521357_eae5_4062_b18a_79a62c261912_createElement = document.createElement.bind(document);
    document.createElement = function(el) {
        aa521357_eae5_4062_b18a_79a62c261912_sanitize(el);
        return aa521357_eae5_4062_b18a_79a62c261912_createElement(el);
    };
    aa521357_eae5_4062_b18a_79a62c261912_getElementsByTagName = Element.prototype.getElementsByTagName;
    Element.prototype.getElementsByTagName = function(el) {
        aa521357_eae5_4062_b18a_79a62c261912_sanitize(el);
        return aa521357_eae5_4062_b18a_79a62c261912_getElementsByTagName.call(this, el);
    };
    aa521357_eae5_4062_b18a_79a62c261912_appendChild = Node.prototype.appendChild;
    Node.prototype.appendChild = function(el) {
        aa521357_eae5_4062_b18a_79a62c261912_sanitize(el);
        return aa521357_eae5_4062_b18a_79a62c261912_appendChild.call(this, el);
    };
}
var script = document.createElement("script");
script.textContent = "(" + main.toString() + ")();";
(document.getElementsByTagName('head')[0] || document.body || document.documentElement).appendChild(script);
```

### proxy

- Alternative for prototype

Adapted from uBlock Origin scriptlet for BlockAdBlock:

```javascript
const check = function(s) {
    // check for signature
};

window.eval = new Proxy(window.eval, {
    apply: function(target, thisArg, args) {
        const a = args[0];
        if ( typeof a !== 'string' || !check(a) ) {
            return target.apply(thisArg, args);
        }
        // BAB detected: clean up.
        if ( document.body ) {
            document.body.style.removeProperty('visibility');
        }
        let el = document.getElementById('babasbmsgx');
        if ( el ) {
            el.parentNode.removeChild(el);
        }
    }
});
window.setTimeout = new Proxy(window.setTimeout, {
    apply: function(target, thisArg, args) {
        const a = args[0];
        // Check that the passed string is not the BAB entrypoint.
        if (
            typeof a !== 'string' ||
            /\.bab_elementid.$/.test(a) === false
        ) {
            return target.apply(thisArg, args);
        }
    }
});
```

## References

- [How an anti ad\-blocker works: Reverse\-engineering BlockAdBlock](https://xy2.dev/article/re-bab/)


