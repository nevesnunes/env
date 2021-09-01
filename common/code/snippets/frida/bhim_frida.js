function bin2string(array){
    var result = "";
    for(var i = 0; i < array.length; ++i){
        result+= (String.fromCharCode(array[i]));
    }
    return result;
}

function string2bin(str){
    var result = [];
    for(var i = 0; i < str.length; ++i)
    result = result.concat([str.charCodeAt(i)]);
    return result;
}

setTimeout( function() {
    Java.perform(function () {
        var act1 = Java.use("in.org.npci.upiapp.utils.RestClient");
        act1.a.overload('org.apache.http.client.methods.HttpRequestBase', 'boolean').implementation = function (arg1, arg2){
            Java.perform(function() {
                console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()))
            });
            console.log(arg1.getURI());
            var h = arg1.getAllHeaders();
            for (var x in h){
                console.log(h[x].getName()+":"+h[x].getValue());
            }
            console.log(">>>>>");
            var ret = this.a(arg1, arg2); 
            console.log(ret);
            var s = bin2string(ret.getData());
            var ss = s.replace('"error":true', '"error":false');
            ss = ss.replace('"verified":false', '"verified":true');
            ret.setData(string2bin(ss));
            console.log(bin2string(ret.getData()));
            console.log(">>>>>");
            return ret;
        };
        var act2 = Java.use("org.apache.http.client.methods.HttpPost");
        act2.setEntity.implementation = function (arg1) {
            console.log(">>>>>setEntity()>>>>>");
            var arr = [];
            var y = arg1.getContent();
            var x = y.read();
            while(x != -1){
                arr.push(x);
                x = y.read();
            }
            console.log(bin2string(arr));
            console.log(">>>>>");
            var ret = this.setEntity(arg1);
            return ret;
        };
        var act3 = Java.use("in.org.npci.upiapp.a.a");
        act3.a.overload("java.lang.String", "java.lang.String").implementation = function(arg1, arg2){
            console.log(arg1);
            console.log(arg2);
        };
    });
},0);
