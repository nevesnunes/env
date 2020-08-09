// ==UserScript==
// @name         Swagger auth
// @namespace    http://tampermonkey.net/
// @version      0.1
// @description  try to take over the world!
// @author       You
// @match        https://*/foo/swagger/dist/index.html
// @match        https://*/*/foo/swagger/dist/index.html
// @grant        none
// ==/UserScript==

(function() {
    function typeInElement(el, str) {
        if (!el) {
            return;
        }

        var nativeInputValueSetter = Object.getOwnPropertyDescriptor(
            window.HTMLInputElement.prototype,
            "value").set;
        nativeInputValueSetter.call(el, str);

        var ev2 = new Event('input', { bubbles: true });
        el.dispatchEvent(ev2);
    }

    var timeoutHandler;
    var tries = 0;
    function main() {
        if (tries > 20) {
            clearTimeout(timeoutHandler);
            return;
        }
        tries++;

        var targetNode = document.querySelector('#swagger-ui section div.swagger-ui div div.scheme-container section div');
        if (!targetNode) {
            return;
        }
        var observer = new MutationObserver(function(){
            var inputUser = document.querySelector('#swagger-ui > section > div.swagger-ui > div > div.scheme-container > section > div > div > div.modal-ux > div > div > div.modal-ux-content > div > form > div:nth-child(1) > div > div:nth-child(5) > section > input[type="text"]');
            if (!inputUser) {
                return;
            }
            typeInElement(inputUser, "foo");
            var inputPass = document.querySelector('#myPassword');
            if (!inputPass) {
                return;
            }
            var passValue = (/localhost/i.test(window.location.href)) ? "password" : "bar";
            typeInElement(inputPass, passValue);
        });
        observer.observe(targetNode, {
            attributes: true,
            childList: true
        });

        clearTimeout(timeoutHandler);
    }
    timeoutHandler = setTimeout(main, 500);
})();
