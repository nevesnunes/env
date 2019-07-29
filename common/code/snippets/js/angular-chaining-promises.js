$http.get('/api/user/name')
  .then(function(response) {
     // Store the username, get the profile.
     details.username = response.data;
     return $http.get('/api/profile/' + details.username);
  })
  .then(function(response) {
      //  Store the profile, now get the permissions.
    details.profile = response.data;
    throw "Oh no! Something failed!";
  })
  .then(function(response) {
      //  Store the permissions
    details.permissions = response.data;
    console.log("The full user details are: " + JSON.stringify(details);
  })
  .catch(function(error) {
    console.log("An error occured: " + error);
  });
