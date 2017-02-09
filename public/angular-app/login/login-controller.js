angular.module('meanhotel').controller('LoginController', LoginController);

function LoginController($http, $location, $window, AuthFactory, jwtHelper) {
  var vm = this;

  vm.isLoggedIn = function() {
    if (AuthFactory.isLoggedIn) {
		console.log(' LoggedIn: '+vm.username);
      return true;
    } else {
// console.log('!LoggedIn: '+vm.username);
      return false;
    }
  };

  vm.login = function() {
    if (vm.username && vm.password) {
      var user = {
        username: vm.username,
        password: vm.password
      };

      $http.post('/api/users/login', user).then(function(response) {
        if (response.data.success) {
          $window.sessionStorage.token = response.data.token;
          AuthFactory.isLoggedIn = true;
          var token = $window.sessionStorage.token;
          var decodedToken = jwtHelper.decodeToken(token);
          vm.loggedInUser = decodedToken.username;
        }
      }).catch(function(error) {
        console.log('login-POST error: '+ error);
      })

    }
  }

  vm.logout = function() {
	  console.log('logout '+ vm.username);
    AuthFactory.isLoggedIn = false;
    delete $window.sessionStorage.token;
    $location.path('/');
  }

  vm.isActiveTab = function(url) {
    var currentPath = $location.path().split('/')[1];
    return (url === currentPath ? 'active' : '');
  }
}
