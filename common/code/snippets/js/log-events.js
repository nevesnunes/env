monitorEvents(document.getElementById('inputId'));

// ||

var items = Array.prototype.slice.call(
    document.querySelectorAll('*')
).map(function(element) {
    var listeners = getEventListeners(element);
    return {
        element: element,
        listeners: Object.keys(listeners).map(function(k) {
            return {
                event: k,
                listeners: listeners[k]
            };
        })
    };
}).filter(function(item) {
    return item.listeners.length;
});

// ||

$('body').on("click mousedown mouseup focus blur keydown change mouseup click dblclick mousemove mouseover mouseout mousewheel keydown keyup keypress textInput touchstart touchmove touchend touchcancel resize scroll zoom focus blur select change submit reset", function(e) {
    console.log(e);
});

// ||

Object.getOwnPropertyNames(input)
    .filter(key => key.slice(0, 2) === 'on')
    .map(key => key.slice(2))
    .forEach(eventName => {
        input.addEventListener(eventName, event => {
            console.log(event.type);
            console.log(event);
        });
    });

// ||

var myEventManager = (function() {
    var old = EventTarget.prototype.addEventListener,
        listeners = [],
        events = [];

    EventTarget.prototype.addEventListener = function(type, listener) {

        function new_listener(listener) {
            return function(e) {
                events.push(e); // remember event
                return listener.call(this, e); // call original listener
            };
        }

        listeners.push([type, listener]); // remember call
        return old.call(this, type, new_listener(listener)); // call original
    };

    return {
        get_events: function() {
            return events;
        },
        get_listeners: function() {
            return listeners;
        }
    };

}());

// ||

function setJQueryEventHandlersDebugHooks(bMonTrigger, bMonOn, bMonOff) {
    jQuery.fn.___getHookName___ = function() {
        // First, get object name
        var sName = new String(this[0].constructor),
            i = sName.indexOf(' ');
        sName = sName.substr(i, sName.indexOf('(') - i);

        // Classname can be more than one, add class points to all
        if (typeof this[0].className === 'string') {
            var sClasses = this[0].className.split(' ');
            sClasses[0] = '.' + sClasses[0];
            sClasses = sClasses.join('.');
            sName += sClasses;
        }
        // Get id if there is one
        sName += (this[0].id) ? ('#' + this[0].id) : '';
        return sName;
    };

    var bTrigger = (typeof bMonTrigger !== "undefined") ? bMonTrigger : true,
        bOn = (typeof bMonOn !== "undefined") ? bMonOn : true,
        bOff = (typeof bMonOff !== "undefined") ? bMonOff : true,
        fTriggerInherited = jQuery.fn.trigger,
        fOnInherited = jQuery.fn.on,
        fOffInherited = jQuery.fn.off;

    if (bTrigger) {
        jQuery.fn.trigger = function() {
            console.log(this.___getHookName___() + ':trigger(' + arguments[0] + ')');
            return fTriggerInherited.apply(this, arguments);
        };
    }

    if (bOn) {
        jQuery.fn.on = function() {
            if (!this[0].__hooked__) {
                this[0].__hooked__ = true; // avoids infinite loop!
                console.log(this.___getHookName___() + ':on(' + arguments[0] + ') - binded');
                $(this).on(arguments[0], function(e) {
                    console.log($(this).___getHookName___() + ':' + e.type);
                });
            }
            var uResult = fOnInherited.apply(this, arguments);
            this[0].__hooked__ = false; // reset for another event
            return uResult;
        };
    }

    if (bOff) {
        jQuery.fn.off = function() {
            if (!this[0].__unhooked__) {
                this[0].__unhooked__ = true; // avoids infinite loop!
                console.log(this.___getHookName___() + ':off(' + arguments[0] + ') - unbinded');
                $(this).off(arguments[0]);
            }

            var uResult = fOffInherited.apply(this, arguments);
            this[0].__unhooked__ = false; // reset for another event
            return uResult;
        };
    }
}
