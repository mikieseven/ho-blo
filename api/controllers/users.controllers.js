var mongoose = require('mongoose');
var User     = mongoose.model('User');
var bcrypt   = require('bcrypt-nodejs');
var jwt      = require('jsonwebtoken');

module.exports.register = function(req, res) {

  var username = req.body.username;
  var name = req.body.name || null;
  var password = req.body.password;
  console.log('Attempting registration: '+ username);

  User.create({
    username: username,
    name: name,
    password: bcrypt.hashSync(password, bcrypt.genSaltSync(10))
  }, function(err, user) {
    if (err) {
      console.log(err);
      res.status(400).json(err);
    } else {
      console.log('user created', user);
      res.status(201).json(user);
    }
  });
};

module.exports.login = function(req, res) {

  var username = req.body.username;
  var password = req.body.password;

  User.findOne({
    username: username
  }).exec(function(err, user) {  
	// Test record: "Zim" is found but does not have encrypted ID; 
	// no err thrown but will crash the app in bcrypt for PW format
	//  console.log('\n findOne return objects: '+ err + ' & '+ user); 
	// User not found - err & user return null
	  
    if (err || !user) { // Check if err || user are null
		if (!user) {
			console.log("Status 400 - notfound " + username );
			res.status(400);
		} else { // log the error
			res.status(400).json(err);
		}
    } else {  // check the PW length == 60 char valid hash format
		if (user.password.length < 60){ // check 4 unencrypted PW
			console.log('Corrupted hash '+ user.password.length);
			res.status(401).json('Fail - hash < 60');
		} else {
			if (bcrypt.compareSync(password, user.password)) { // hash format input
				console.log('Accepted: ', user.username);
				var token = jwt.sign({ username: user.username }, 's3cr3t', { expiresIn: 3600 });
				res.status(200).json({success: true, token: token});
			} else {
				console.log('Authentication PW Failed');
				res.status(401).json('Authentication PW Fail');
			}
		}
	}
  });
}; 

// IF, a user w/ 60 char bcrypt hash of plaintext PW 
   // could be inserted into the users DB, to pass the bcrypt comparison
   // would a token be issued for that username?  
   // The answer here is YES, YES, YES.
   
   // first gain root access to the MongoDB instance
   // Register a user with PW == "whatever"
   // Create a new user json object for mongoimport 
   // use the "whatever" hash value from the registered user in the new user object
   // mongoimport the new user.json to the users collection
   // login to the app as new user with "whatever" as PW
   // a token will be issued to the new user ID
   
   // What if and unsecured public facing MongoDB upserted a new root admin json?
   // e.g. on a new instance of Bitnami or Strongloop MEAN stack

module.exports.authenticate = function(req, res, next) {
  var headerExists = req.headers.authorization;
  if (headerExists) {
    var token = req.headers.authorization.split(' ')[1]; //--> Authorization Bearer xxx
    jwt.verify(token, 's3cr3t', function(error, decoded) {
      if (error) {
        console.log(error);
        res.status(401).json('Unauthorized');
      } else {
        req.user = decoded.username;
        next();
      }
    });
  } else {
    res.status(403).json('No token provided');
  }
};
