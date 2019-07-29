// ==UserScript==
// @name          Inline Image Relinker
// @namespace     /web/20070712085327/http://www.sitzmar.com
// @description   Replaces links to images with the actual image
// @include       *
// ==/UserScript==

(function() {
    function getXPath(p, context) {
        var arr = new Array();
        var xpr = document.evaluate(p, context, null, XPathResult.UNORDERED_NODE_SNAPSHOT_TYPE, null);
        for (i = 0; item = xpr.snapshotItem(i); i++) {
            arr.push(item);
        }

        return arr;
    }

    var xpath = "//A[(contains(@href, '.jpg') or contains(@href, '.jpeg') or contains(@href, '.gif') or contains(@href, '.bmp') or contains(@href, '.png')) and not(contains(@href, '.php') or contains(@href, '.asp'))]";
    results = getXPath(xpath, document);
    for (i = 0; i < results.length; i++) {
        var img = document.createElement("img");
        var source = results[i].getAttribute("href");
        img.setAttribute("src", source);
        img.setAttribute("class", "what");
        results[i].textContent = "";
        results[i].appendChild(img);
    }
})();
