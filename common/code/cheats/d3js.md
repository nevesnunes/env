# lifecycle - deleting elements + handlers

d3.select("svg").remove();
// ||
svg.selectAll("*").remove();
svg = null;

d3.selectAll(".nodes").on('click',null);

https://github.com/d3/d3/wiki#on
