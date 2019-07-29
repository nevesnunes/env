function addJQuery(callback) {
    var script = document.createElement("script");
    script.setAttribute("src", "//ajax.googleapis.com/ajax/libs/jquery/1/jquery.min.js");
    script.addEventListener('load', function() {
        var script = document.createElement("script");
        script.textContent = "window.jQ=jQuery.noConflict(true);(" + callback.toString() + ")();";
        document.body.appendChild(script);
    }, false);
    document.body.appendChild(script);
}

function main() {
    jQ(document).ready(function() {
        var observeDOM = (function() {
            var MutationObserver = window.MutationObserver || window.WebKitMutationObserver,
                eventListenerSupported = window.addEventListener;

            return function(obj, callback) {
                if (MutationObserver) {
                    // define a new observer
                    var obs = new MutationObserver(function(mutations, observer) {
                        if (mutations[0].addedNodes.length || mutations[0].removedNodes.length)
                            callback(mutations);
                    });
                    // have the observer observe foo for changes in children
                    obs.observe(obj, {
                        childList: true,
                        subtree: true
                    });
                } else if (eventListenerSupported) {
                    obj.addEventListener('DOMNodeInserted', callback, false);
                    obj.addEventListener('DOMNodeRemoved', callback, false);
                }
            };
        })();
        observeDOM(document.body, function(mutations) {
            var needle = "seeMoreBtn";
            var observeEvent = new CustomEvent('aa521357_eae5_4062_b18a_79a62c261912');
            document.addEventListener('aa521357_eae5_4062_b18a_79a62c261912', function (elem) {
                console.log("Found seeMoreBtn");
            }, false);

            if (!mutations) {
                return;
            }
            var recursivePrint = function(el) {
                var re = new RegExp(needle);
                if (!el) {
                    return;
                }
                if (el.className && re.test(el.className)) {
                    document.dispatchEvent(observeEvent);
                }
                if (!el.children) {
                    return;
                }
                for (var i = 0; i < el.children.length; i++) {
                    recursivePrint(el.children[i]);
                }
            };
            for (var i = 0; i < mutations.length; i++) {
                var m = mutations[i];
                for (var j = 0; j < m.addedNodes.length; j++) {
                    recursivePrint(m.addedNodes[j]);
                }
            }
        });
    });
}

addJQuery(main);
