function simulateKeyEvent(character) {
    var evt = document.createEvent("KeyboardEvent");
    (evt.initKeyEvent || evt.initKeyboardEvent)("keypress", true, true, window,
                                                0, 0, 0, 0,
                                                0, character.charCodeAt(0));
    var canceled = !document.body.dispatchEvent(evt);
    if (canceled) {
        // A handler called preventDefault
        console.log("keyEvent canceled");
    }
}

el.focus();
for (var i = 0; i < str.length; i++) {
    simulateKeyEvent(str.charAt(i));
}
