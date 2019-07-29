function(scope, element, attrs) {  
  element.on('click', function() {
    scope.selected = true;
  });
  scope.$on('$destroy', function() {
      element.off(); // deregister all event handlers
  })''
}
