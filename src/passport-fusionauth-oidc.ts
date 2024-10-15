import * as OAuth2Strategy from 'passport-oauth2'

export interface PassportOIDCSettings {
	clientId: string;
	clientSecret: string;
	emailClaim: string;
	authorizationEndpoint: string;
	tokenEndpoint: string;
	userInfoEndpoint: string;
	callbackURL: string;
	scope: string;
}

export class PassportOIDC extends OAuth2Strategy {
	public name = "passport-oidc";

	constructor(private settings: PassportOIDCSettings, verifyFunction: OAuth2Strategy.VerifyFunctionWithRequest) {
		super({
			clientID: settings.clientId,
			clientSecret: settings.clientSecret,
			callbackURL: settings.callbackURL,
			authorizationURL: settings.authorizationEndpoint,
			tokenURL: settings.tokenEndpoint,
			scope: settings.scope.split(' '),
			passReqToCallback: true,
			skipUserProfile: true,
		}, verifyFunction);
	}

	// Just to remember these exist
	// tokenParams(options: any): object {
	// 	return super.tokenParams(options);
	// }

	// Just to remember these exist
	// authorizationParams(options: any): object {
	// 	return super.authorizationParams(options);
	// }

	userProfile(accessToken: string, done: (err?: (Error | null), profile?: any) => void): void {
		if (!accessToken) {
			done(new Error('Missing token, cannot call the userinfo endpoint without it.'));
		}

		this._oauth2.useAuthorizationHeaderforGET(true);
		this._oauth2.get(this.settings.userInfoEndpoint, accessToken, (err, body, res) => {
			if (err) {
				console.error(err);
				return done(new Error(`Failed to get user info. Exception was previously logged.`));
			}

			if (res.statusCode > 299 || res.statusCode < 200) {
				return done(new Error(`Unexpected response from userInfo. [${res.statusCode}] [${body}]`))
			}

			try {
				done(null, JSON.parse(body as string));
			} catch (e) {
				console.error(e);
				done(new Error(`Failed to parse the userinfo body. Exception was previously logged.`));
			}
		});
	}

	authenticate(req, options) {
		options = options || {};
		var self = this;
	  
		if (req.query && req.query.error) {
		  if (req.query.error == 'access_denied') {
			return this.fail({ message: req.query.error_description });
		  } else {
			return this.error(new AuthorizationError(req.query.error_description, req.query.error, req.query.error_uri));
		  }
		}
	  
		var callbackURL = options.callbackURL || this._callbackURL;
		if (callbackURL) {
		  var parsed = url.parse(callbackURL);
		  if (!parsed.protocol) {
			// The callback URL is relative, resolve a fully qualified URL from the
			// URL of the originating request.
			callbackURL = url.resolve(utils.originalURL(req, { proxy: this._trustProxy }), callbackURL);
		  }
		}
	  
		var meta = {
		  authorizationURL: this._oauth2._authorizeUrl,
		  tokenURL: this._oauth2._accessTokenUrl,
		  clientID: this._oauth2._clientId,
		  callbackURL: callbackURL
		}
	  
		if ((req.query && req.query.code) || (req.body && req.body.code)) {
		  function loaded(err, ok, state) {
			if (err) { return self.error(err); }
			if (!ok) {
			  return self.fail(state, 403);
			}
	  
			var code = (req.query && req.query.code) || (req.body && req.body.code);
	  
			var params = self.tokenParams(options);
			params.grant_type = 'authorization_code';
			if (callbackURL) { params.redirect_uri = callbackURL; }
			if (typeof ok == 'string') { // PKCE
			  params.code_verifier = ok;
			}
	  
			self._oauth2.getOAuthAccessToken(code, params,
			  function(err, accessToken, refreshToken, params) {
				if (err) { return self.error(self._createOAuthError('Failed to obtain access token', err)); }
				if (!accessToken) { return self.error(new Error('Failed to obtain access token')); }
	  
				self._loadUserProfile(accessToken, function(err, profile) {
				  if (err) { return self.error(err); }
	  
				  function verified(err, user, info) {
					if (err) { return self.error(err); }
					if (!user) { return self.fail(info); }
	  
					info = info || {};
					if (state) { info.state = state; }
					self.success(user, info);
				  }
	  
				  try {
					if (self._passReqToCallback) {
					  var arity = self._verify.length;
					  if (arity == 6) {
						self._verify(req, accessToken, refreshToken, params, profile, verified);
					  } else { // arity == 5
						self._verify(req, accessToken, refreshToken, profile, verified);
					  }
					} else {
					  var arity = self._verify.length;
					  if (arity == 5) {
						self._verify(accessToken, refreshToken, params, profile, verified);
					  } else { // arity == 4
						self._verify(accessToken, refreshToken, profile, verified);
					  }
					}
				  } catch (ex) {
					return self.error(ex);
				  }
				});
			  }
			);
		  }
	  
		  var state = (req.query && req.query.state) || (req.body && req.body.state);
		  try {
			var arity = this._stateStore.verify.length;
			if (arity == 4) {
			  this._stateStore.verify(req, state, meta, loaded);
			} else { // arity == 3
			  this._stateStore.verify(req, state, loaded);
			}
		  } catch (ex) {
			return this.error(ex);
		  }
		} else {
		  var params = this.authorizationParams(options);
		  params.response_type = 'token';
		  if (callbackURL) { params.redirect_uri = callbackURL; }
		  var scope = options.scope || this._scope;
		  if (scope) {
			if (Array.isArray(scope)) { scope = scope.join(this._scopeSeparator); }
			params.scope = scope;
		  }
		  var verifier, challenge;
	  
		  if (this._pkceMethod) {
			verifier = base64url(crypto.pseudoRandomBytes(32))
			switch (this._pkceMethod) {
			case 'plain':
			  challenge = verifier;
			  break;
			case 'S256':
			  challenge = base64url(crypto.createHash('sha256').update(verifier).digest());
			  break;
			default:
			  return this.error(new Error('Unsupported code verifier transformation method: ' + this._pkceMethod));
			}
			
			params.code_challenge = challenge;
			params.code_challenge_method = this._pkceMethod;
		  }
	  
		  var state = options.state;
		  if (state && typeof state == 'string') {
			// NOTE: In passport-oauth2@1.5.0 and earlier, `state` could be passed as
			//       an object.  However, it would result in an empty string being
			//       serialized as the value of the query parameter by `url.format()`,
			//       effectively ignoring the option.  This implies that `state` was
			//       only functional when passed as a string value.
			//
			//       This fact is taken advantage of here to fall into the `else`
			//       branch below when `state` is passed as an object.  In that case
			//       the state will be automatically managed and persisted by the
			//       state store.
			params.state = state;
			
			var parsed = url.parse(this._oauth2._authorizeUrl, true);
			utils.merge(parsed.query, params);
			parsed.query['client_id'] = this._oauth2._clientId;
			delete parsed.search;
			var location = url.format(parsed);
			this.redirect(location);
		  } else {
			function stored(err, state) {
			  if (err) { return self.error(err); }
	  
			  if (state) { params.state = state; }
			  var parsed = url.parse(self._oauth2._authorizeUrl, true);
			  utils.merge(parsed.query, params);
			  parsed.query['client_id'] = self._oauth2._clientId;
			  delete parsed.search;
			  var location = url.format(parsed);
			  self.redirect(location);
			}
	  
			try {
			  var arity = this._stateStore.store.length;
			  if (arity == 5) {
				this._stateStore.store(req, verifier, state, meta, stored);
			  } else if (arity == 4) {
				this._stateStore.store(req, state, meta, stored);
			  } else if (arity == 3) {
				this._stateStore.store(req, meta, stored);
			  } else { // arity == 2
				this._stateStore.store(req, stored);
			  }
			} catch (ex) {
			  return this.error(ex);
			}
		  }
		}
	  }
}

export default PassportOIDC;
