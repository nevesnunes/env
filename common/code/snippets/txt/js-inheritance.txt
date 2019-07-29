Parent = (function () {
    // constructor
    function construct () {
        console.log("Parent");
    };

    // public functions
    construct.prototype.test = function () {
        console.log("test parent");
    };
    construct.prototype.test2 = function () {
        console.log("test2 parent");
    };

    return construct;
})();


Child = (function () {
    // constructor
    function construct() {
        console.log("Child");
        Parent.apply(this, arguments);
    }

    // make the prototype object inherit from the Parent's one
    construct.prototype = Object.create(Parent.prototype);
    // public functions
    construct.prototype.test = function() {
        console.log("test Child");
    };

    return construct;
})();
