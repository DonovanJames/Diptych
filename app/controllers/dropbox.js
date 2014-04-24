var fs = require('fs')
,	dbox  = require('dbox')
,	http = require('http')
,	config = require('../../config/config.js')
,	crypto = require('crypto')
,	request = require('request')
,	url = require('url')
,	app_path = 'http://localhost:3000'
;

/*
Dropbox uses OAuth for a 3-step flow:
	1. Obtaining a temporary request token
	2. Directing the user to dropbox.com to authorize your app
	3. Acquiring a permanent access token
*/

// Step 1
// Read Dropbox keys into the configuration protocol.
var APP_KEY = fs.readFileSync('./dropbox_app_key.txt').toString();
var APP_SECRET = fs.readFileSync('./dropbox_app_secret.txt').toString();
// populate dropbox helper app with secret keys
var dropbox = dbox.app({ "app_key" : APP_KEY, "app_secret" : APP_SECRET });


// Step 2 
function requestToken(request, responce){
	dropbox.requesttoken(function(status, request_token){
		// storing the returned request token in a session cookie for use in the next step
		responce.writeHead(200, {
			"Set-Cookie" : ["oat=" + request_token.oauth_token,
							"oats=" + request_token.oauth_token_secret]
		});
		//redirection happens by writing a piece of javascript to our http responce
		responce.write(	"<script>window.location='https://www.dropbox.com/1/oauth/authorize"+
					"?oauth_token=" + request_token.oauth_token + 
					"&oauth_callback=" + app_path + "/authorized';</script>");
		responce.end();
	});
}

function accessToken(req, res) {
    var req_token = {oauth_token : req.cookies.oat, oauth_token_secret : req.cookies.oats};
    dropbox.accesstoken(req_token, function(status, access_token) {
        if (status == 401) {
            res.write("Sorry, Dropbox reported an error: " + JSON.stringify(access_token));
        }
        else {
            var expiry = new Date(Date.now() + 1000 * 60 * 60 * 24 * 30); // 30 days
            res.writeHead(302, {
                "Set-Cookie" : "uid=" + access_token.uid + "; Expires=" + expiry.toUTCString(),
                "Location" : "/"
            });
            // db.collection("user", function(err, collection) {
            //     var entry = {};
            //     entry.uid = access_token.uid;
            //     entry.oauth_token = access_token.oauth_token;
            //     entry.oauth_token_secret = access_token.oauth_token_secret;
            //     collection.update({"uid": access_token.uid}, {$set: entry}, {upsert:true});
            // });
        }
        res.end();
    });
}



// https://github.com/smarx/othw/blob/master/Node.js/app.js
function generateCSRFToken() {
	return crypto.randomBytes(18).toString('base64')
		.replace(/\//g, '-').replace(/\+/g, '_');
}

function generateRedirectURI(request) {
	return url.format({
			protocol: request.protocol,
			host: request.headers.host,
			pathname: '/callback'
	});
}

function defaultOauth(request, response) {
	var csrfToken = generateCSRFToken();
	response.cookie('csrf', csrfToken);
	response.redirect(url.format({
		protocol: 'https',
		hostname: 'www.dropbox.com',
		pathname: '1/oauth2/authorize',
		query: {
			client_id: APP_KEY,
			response_type: 'code',
			state: csrfToken,
			redirect_uri: generateRedirectURI(request)
		}
	}));
}

function oauthCallback(request, response) {
	if (request.query.error) {
		return response.send('ERROR ' + request.query.error + ': ' + request.query.error_description);
	}

	// check CSRF token
	if (request.query.state !== request.cookies.csrf) {
		return response.status(401).send(
			'CSRF token mismatch, possible cross-site request forgery attempt.'
		);
	}
	// exchange access code for bearer token
	request.post('https://api.dropbox.com/1/oauth2/token', {
		form: {
			code: request.query.code,
			grant_type: 'authorization_code',
			redirect_uri: generateRedirectURI(request)
		},
		auth: {
			user: APP_KEY,
			pass: APP_SECRET
		}
	}, function (error, response, body) {
		var data = JSON.parse(body);

		if (data.error) {
			return response.send('ERROR: ' + data.error);
		}

		// extract bearer token
		var token = data.access_token;

		// use the bearer token to make API calls
		request.get('https://api.dropbox.com/1/account/info', {
			headers: { Authorization: 'Bearer ' + token }
		}, function (error, response, body) {
			response.send('Logged in successfully as ' + JSON.parse(body).display_name + '.');
		});
	});
}


exports.defaultOauth = defaultOauth;
exports.oauthCallback = oauthCallback;
exports.requestToken = requestToken;
exports.accessToken = accessToken;

