// Reference:
// https://stackoverflow.com/a/36860652/8020917
function getRelativeCoordinates (event, element){

  const position = {
    x: event.pageX,
    y: event.pageY
  };

  const offset = {
    left: element.offsetLeft,
    top: element.offsetTop
  };

  let reference = element.offsetParent;

  while(reference != null){
    offset.left += reference.offsetLeft;
    offset.top += reference.offsetTop;
    reference = reference.offsetParent;
  }

  return { 
    x: position.x - offset.left,
    y: position.y - offset.top,
  }; 

}

var movable = document.querySelector('#movable');
var target = document.querySelector('#target');
var middleTarget = target.offsetWidth / 2;
target.addEventListener('mousemove', function(evt) {
    var x = getRelativeCoordinates(evt, target).x - middleTarget;
    console.log(x);
    movable.style.left = (x * movable.offsetWidth / target.offsetWidth * 1.5 - middleTarget) + 'px';
});
