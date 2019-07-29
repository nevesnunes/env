$("div").find("span").toArray().reduce(function(a, b) { return a += " " + b.innerHTML; }, "")
