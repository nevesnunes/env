let vW = $(window).width();

$(document).on("mousemove", function(e) {
  let mW = ((((event.pageX)*100)/vW).toFixed(3))-50;
  $("#red").css('transform',	'translateX(' +(-mW/2)+ '%)');
});
