// change and name and wait for the result
UserService.changeName("Fry").then(function(newName) {  
    $scope.name = newName;
});
The notification service returns a promise (a short lived object) when holds the closure. If we get things wrong, we are less likely to leak the scope. Plus, promises are typically easy to work with once you've got the hang of them
