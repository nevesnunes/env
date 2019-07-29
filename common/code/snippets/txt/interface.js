// example duck typing method
var hasMethods = function(obj /*, method list as strings */){
    var i = 1, methodName;
    while((methodName = arguments[i++])){
        if(typeof obj[methodName] != 'function') {
            return false;
        }
    }
    return true;
}

// in your code
if(hasMethods(obj, 'quak', 'flapWings','waggle')) {
    //  IT'S A DUCK, do your duck thang
}
