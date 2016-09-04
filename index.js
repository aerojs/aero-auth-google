let passport = require('passport')
let GoogleStrategy = require('passport-google-oauth').OAuth2Strategy

module.exports = app => {
	app.on('startup loaded', () => {
		if(!app.auth || !app.auth.google)
			throw new Error('Missing Google configuration. Please define app.auth.google')

		if(!app.api.google || !app.api.google.id || !app.api.google.secret)
			throw new Error('Missing Google API keys. Please add them to security/api-keys.json')

		if(!app.auth.google.login)
			throw new Error("app.auth.google.login needs to be defined")

		if(app.auth.google.login.constructor.name === 'GeneratorFunction')
			app.auth.google.login = Promise.coroutine(app.auth.google.login)

		let config = {
			callbackURL: app.production ? `https://${app.config.domain}/auth/google/callback` : '/auth/google/callback',
			passReqToCallback: true,
			clientID: app.api.google.id,
			clientSecret: app.api.google.secret
		}

		// Register Google strategy
		passport.use(new GoogleStrategy(config,
			function(request, accessToken, refreshToken, profile, done) {
				app.auth.google.login(profile._json)
				.then(user => done(undefined, user))
				.catch(error => done(error, false))
			}
		))

		// Google login
		app.get('/auth/google', passport.authenticate('google', {
			scope: app.auth.google.scopes || [
				'https://www.googleapis.com/auth/plus.login',
				'email'
			]
		}))

		// Google callback
		app.get('/auth/google/callback',
			passport.authenticate('google', app.auth.google.onLogin || { successRedirect: '/' })
		)
	})
}