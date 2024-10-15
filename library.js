'use strict';

((module) => {
	const User = require.main.require('./src/user');
	const Groups = require.main.require('./src/groups');
	const db = require.main.require('./src/database');
	const authenticationController = require.main.require('./src/controllers/authentication');
	const Settings = require.main.require('./src/settings');

	const async = require('async');
	const { PassportOIDC } = require('./src/passport-fusionauth-oidc');

	const passport = module.parent.require('passport');
	const nconf = module.parent.require('nconf');
	const winston = module.parent.require('winston');

	const constants = {
		name: 'fusionauth-oidc',
		callbackURL: '/auth/oidc/callback',
		pluginSettingsURL: '/admin/plugins/fusionauth-oidc',
		pluginSettings: new Settings('fusionauth-oidc', '1.0.0', {
			// Default settings
			clientId: '',
			clientSecret: '',
			emailClaim: 'email',
			discoveryBaseURL: '',
			authorizationEndpoint: '',
			tokenEndpoint: '',
			userInfoEndpoint: '',
			scope: 'openid email profile offline_access',
		}, false, false),
	};

	const Oidc = {};

	/**
	 * Sets up the router bindings for the settings page
	 * @param params
	 * @param callback
	 */
	Oidc.init = function (params, callback) {
		winston.verbose('Setting up FusionAuth OIDC bindings/routes');

		function render(req, res) {
			res.render('admin/plugins/fusionauth-oidc', {
				baseUrl: nconf.get('url'),
			});
		}

		params.router.get(constants.pluginSettingsURL, params.middleware.admin.buildHeader, render);
		params.router.get('/api/admin/plugins/fusionauth-oidc', render);

		callback();
	};

	/**
	 * Binds the passport strategy to the global passport object
	 * @param strategies The global list of strategies
	 * @param callback
	 */
	Oidc.bindStrategy = function (strategies, callback) {
		winston.verbose('Setting up openid connect');

		callback = callback || function () {
		};

		constants.pluginSettings.sync(function (err) {
			if (err) {
				return callback(err);
			}

			const settings = constants.pluginSettings.getWrapper();

			// If we are missing any settings
			if (!settings.clientId ||
				!settings.clientSecret ||
				!settings.emailClaim ||
				!settings.authorizationEndpoint ||
				!settings.tokenEndpoint ||
				!settings.userInfoEndpoint ||
				!settings.scope) {
				winston.info('OpenID Connect will not be available until it is configured!');
				return callback(null, strategies);
			}

			settings.callbackURL = nconf.get('url') + constants.callbackURL;

			// If you call this twice it will overwrite the first.
			passport.use(constants.name, new PassportOIDC(settings, (req, accessToken, refreshToken, profile, callback) => {
				const email = profile[settings.emailClaim || 'email'];
				const isAdmin = settings.rolesClaim ? (profile[settings.rolesClaim] === 'admin' || (profile[settings.rolesClaim] && profile[settings.rolesClaim].some && profile[settings.rolesClaim].some((value) => value === 'admin'))) : false;
				Oidc.login({
					oAuthid: profile.sub,
					username: profile.name || email.split('@')[0],
					email: email,
					rolesEnabled: settings.rolesClaim && settings.rolesClaim.length !== 0,
					isAdmin: isAdmin,
				}, (err, user) => {
					if (err) {
						return callback(err);
					}

					authenticationController.onSuccessfulLogin(req, user.uid);
					callback(null, user);
				});
			}));

			// If we are doing the update, strategies won't be the right object so
			if (strategies.push) {
				strategies.push({
					name: constants.name,
					url: '/auth/' + constants.name,
					callbackURL: constants.callbackURL,
					icon: 'fa-openid',
					icons: {
						normal: 'fa fa-openid',
						square: 'fa fa-openid',
					},
					labels: {
						login: 'OIDC Log In',
						register: 'OIDC Register',
					},
					scope: settings.scope.split(' '),
				});
			}

			callback(null, strategies);
		});
	};

	Oidc.login = function (payload, callback) {
		async.waterfall([
			// Lookup user by existing oauthid
			(callback) => Oidc.getUidByOAuthid(payload.oAuthid, callback),
			// Skip if we found the user in the pevious step or create the user
			function (uid, callback) {
				if (uid !== null) {
					// Existing user
					callback(null, uid);
				} else {
					// New User
					if (!payload.email) {
						return callback(new Error('The email was missing from the user, we cannot log them in.'));
					}

					async.waterfall([
						(callback) => User.getUidByEmail(payload.email, callback),
						function (uid, callback) {
							if (!uid) {
								User.create({
									username: payload.username,
									email: payload.email,
								}, callback);
							} else {
								callback(null, uid); // Existing account -- merge
							}
						},
						function (uid, callback) {
							// Save provider-specific information to the user
							User.setUserField(uid, constants.name + 'Id', payload.oAuthid);
							db.setObjectField(constants.name + 'Id:uid', payload.oAuthid, uid);

							callback(null, uid);
						},
					], callback);
				}
			},
			// Get the users membership status to admins
			(uid, callback) => Groups.isMember(uid, 'administrators', (err, isMember) => {
				callback(err, uid, isMember);
			}),
			// If the plugin is configured to use roles, add or remove them from the admin group (if necessary)
			(uid, isMember, callback) => {
				if (payload.rolesEnabled) {
					if (payload.isAdmin === true && !isMember) {
						Groups.join('administrators', uid, (err) => {
							callback(err, uid);
						});
					} else if (payload.isAdmin === false && isMember) {
						Groups.leave('administrators', uid, (err) => {
							callback(err, uid);
						});
					} else {
						// Continue
						callback(null, uid);
					}
				} else {
					// Continue
					callback(null, uid);
				}
			},
		], function (err, uid) {
			if (err) {
				return callback(err);
			}
			callback(null, {
				uid: uid,
			});
		});
	};

	Oidc.getUidByOAuthid = function (oAuthid, callback) {
		db.getObjectField(constants.name + 'Id:uid', oAuthid, (err, uid) => {
			if (err) {
				return callback(err);
			}
			callback(null, uid);
		});
	};

	Oidc.deleteUserData = function (data, callback) {
		async.waterfall([
			async.apply(User.getUserField, data.uid, constants.name + 'Id'),
			(oAuthIdToDelete, next) => {
				db.deleteObjectField(constants.name + 'Id:uid', oAuthIdToDelete, next);
			},
		], (err) => {
			if (err) {
				winston.error('[sso-oauth] Could not remove OAuthId data for uid ' + data.uid + '. Error: ' + err);
				return callback(err);
			}

			callback(null, data);
		});
	};

	// If this filter is not there, the deleteUserData function will fail when getting the oauthId for deletion.
	Oidc.whitelistFields = function (params, callback) {
		params.whitelist.push(constants.name + 'Id');
		callback(null, params);
	};

	Oidc.bindMenuOption = function (header, callback) {
		winston.verbose('Binding menu option');
		header.authentication.push({
			route: constants.pluginSettingsURL.replace('/admin', ''), // They will add the /admin for us
			name: 'OpenID Connect',
		});

		callback(null, header);
	};

	/*
	Oidc.redirectLogout = function (payload, callback) {
		const settings = constants.pluginSettings.getWrapper();

		if (settings.logoutEndpoint) {
			winston.verbose('Changing logout to OpenID logout');
			let separator;
			if (settings.logoutEndpoint.indexOf('?') === -1) {
				separator = '?';
			} else {
				separator = '&';
			}
			payload.next = settings.logoutEndpoint + separator + 'client_id=' + settings.clientId;
		}

		return callback(null, payload);
	};
	*/

	module.exports = Oidc;
})(module);
