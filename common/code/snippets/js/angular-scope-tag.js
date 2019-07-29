angular.module('app')  
.controller('TopRatedController', function($scope, $http, $interval) {

  //  Create a class, assign it to the scope. This'll help us 
  //  see if $scope is leaked.
  function TopRatedControllerTag() {}
  $scope.__tag = new TopRatedControllerTag();

  //  etc...
});
