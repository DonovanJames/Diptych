module.exports = function(app){
    var vote = require('../app/controllers/vote')
    ,   photos = require('../app/controllers/photos')
    ,   home = require('../app/controllers/home')
	,   gallery = require('../app/controllers/gallery')
    ,   dropbox = require('../app/controllers/dropbox')

    //home route
    app.get('/', photos.render)
    app.get('/index', photos.render)
    app.get('/photo/next', photos.next)
    app.get('/photo/pair', photos.pair)
    app.get('/photo/pick/:count', photos.pick)

    // Three primary user interactions for photo diptych
    app.get('/keep/:winner/:looser', vote.keep)
    app.get('/toss/:partner1/:partner2', vote.toss)
    app.get('/pair/:partner1/:partner2', vote.pair)


	app.get('/gallery', gallery.list)
	app.get('/rank', gallery.rank)

    // call back from dropbox authorization
    app.get('/authorize', dropbox.requestToken)
    app.get('/authorized', dropbox.accessToken)
    app.get('/oauth', dropbox.defaultOauth)
    app.get('/callback', dropbox.oauthCallback)

};
