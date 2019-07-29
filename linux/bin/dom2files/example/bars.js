var makeBars = function(dataObj, i) {
    var name = dataObj.name;
    var data = dataObj.values;

    //set up svg using margin conventions;
    //we'll need plenty of room on the left for labels
    var margin = {
        top: 10,
        right: 40,
        bottom: 0,
        left: 120
    };

    var axisLabelMarginX = dataObj.axisLabelMarginX;
    var axisLabelMarginY = 40;
    var width = 500 - axisLabelMarginX - margin.left - margin.right,
        height = (30 * data.length) + margin.top - margin.bottom;

    var svg = d3.select("#graphic").append("div")
        .style("display", "block")
        .append("svg")
            .attr("width", width + margin.left + margin.right + axisLabelMarginX)
            .attr("height", height + margin.top + margin.bottom + axisLabelMarginY)
            .append("g")
            .attr("transform", "translate(" + (margin.left + axisLabelMarginX) + "," + margin.top + ")");

    var domainMax = 5;
    var x = d3.scale.linear()
        .range([0, width])
        .domain([0, domainMax]);
    var y = d3.scale.ordinal()
        .rangeRoundBands([height, 0], 0.2)
        .domain(data.map(function(d, i) {
            return d[0] + d[1];
        }));

    //make y axis to show bar names
    var yAxis = d3.svg.axis()
        .scale(y)
        .tickFormat(function(d, i) {
            return d.replace(/correct|incomplete|fail/gi,'');
        })
        .tickSize(1)
        .tickPadding(5)
        .orient("left");

    var gy = svg.append("g")
        .attr("class", "y axis")
        .call(yAxis);

    // text label for the y axis
    svg.append("text")             
        .attr("class", "axis-label")
        .attr("transform",
              "translate(" + -(margin.left + axisLabelMarginX) + " ," + 
                             (height/2) + ")")
        .style("text-anchor", "start")
        .text(name);

    // text label for the x axis
    svg.append("text")             
        .attr("class", "axis-label")
        .attr("transform",
              "translate(" + (width/2) + " ," + 
                             (height + margin.top + 20) + ")")
        .style("text-anchor", "middle")
        .text("Number of users");

    var bars = svg.selectAll(".bar")
        .data(data)
        .enter()
        .append("g");

    //append rects
    bars.append("rect")
        .attr("class", "bar")
        .style("fill", function(d) { return d[3]; })
        .attr("y", function (d) {
            return y(d[0] + d[1]);
        })
        .attr("height", y.rangeBand())
        .attr("x", 0)
        .attr("width", function (d) {
            return x(d[2]);
        });

    //add a value label to the right of each bar
    bars.append("text")
        .attr("class", "label")
        //y position of the label is halfway down the bar
        .attr("y", function (d) {
            return y(d[0] + d[1]) + y.rangeBand() / 2 + 5;
        })
        //x position is 3 pixels to the right of the bar
        .attr("x", function (d) {
            return x(d[2]) + 5;
        })
        .text(function (d) {
            return d[2];
        });

    //add a value label to the left of each bar
    bars.append("text")
        .attr("class", "label")
        //y position of the label is halfway down the bar
        .attr("y", function (d) {
            return y(d[0] + d[1]) + y.rangeBand() / 2 + 5;
        })
        //x position is 3 pixels to the right of the bar
        .attr("x", function (d) {
            return -axisLabelMarginX - 40;
        })
        .text(function (d, i) {
            return ((i - 2) % 3 === 0) ? d[0] : '';
        });
};

d3.csv('testes1.csv', function(error, data) {
    datas = [];
    for (i = 0; i < data.length; i+=3) {
        var array = data.slice(i, i+3);
        var obj = array.reduce(function(acc, obj) {
            acc.values = acc.values.concat([
                [obj.Result, "IP", obj.IP, "#1b9e77"],
                [obj.Result, "LBC", obj.LBC, "#d95f02"],
                [obj.Result, "SD", obj.SD, "#7570b3"]
            ]);
            return acc;
        }, {
            name: "Task " + array[0].Task,
            axisLabelMarginX: 80,
            values: []
        });
        datas.push(obj);
    }
    //datas.forEach(makeBars);
});

d3.csv('testes2.csv', function(error, data) {
    datas = [];
    for (i = 0; i < data.length; i+=3) {
        var array = data.slice(i, i+3);
        var obj = array.reduce(function(acc, obj) {
            acc.values = acc.values.concat([
                [obj.Result, "LNLG", obj.LNLG, "#1b9e77"],
                [obj.Result, "TLC", obj.TLC, "#d95f02"],
                [obj.Result, "SMH", obj.SMH, "#7570b3"]
            ]);
            return acc;
        }, {
            name: "Task " + array[0].Task,
            axisLabelMarginX: 80,
            values: []
        });
        datas.push(obj);
    }
    datas.forEach(makeBars);
});
