<div class="row">
	<div class="col-xs-12">
		<div class="panel panel-default">
			<div class="panel-heading">
				<h2 class="panel-title">OpenID Connect Configuration</h2>
			</div>
			<div class="panel-body">
				<p>
					Configure NodeBB to authenticate using an OpenID Connect identity provider.
				</p>
				<form class="mt-3" id="fusionauth-oidc-settings" role="form">
					<div class="mb-2">
						<label class="form-label" for="client_id">Client Id</label>
						<input class="form-control" data-trim="true" id="client_id" name="clientId" type="text">
					</div>
					<div class="mb-2">
						<label class="form-label" for="client_secret">Client Secret</label>
						<input class="form-control" data-trim="true" id="client_secret" name="clientSecret" type="text">
					</div>
					<div class="mb-2">
						<label class="form-label" for="discovery_base_url">Discovery URL</label>
						<input class="form-control" data-trim="true" id="discovery_base_url" name="discoveryBaseURL" type="text">
					</div>
					<div class="mb-2">
						<label class="form-label" for="authorization_endpoint">Authorization endpoint</label>
						<input class="form-control" data-trim="true" id="authorization_endpoint" name="authorizationEndpoint"
						       type="text">
					</div>
					<div class="mb-2">
						<label class="form-label" for="token_endpoint">Token endpoint</label>
						<input class="form-control" data-trim="true" id="token_endpoint" name="tokenEndpoint" type="text">
					</div>
					<div class="mb-2">
						<label class="form-label" for="user_info_endpoint">Userinfo endpoint</label>
						<input class="form-control" data-trim="true" id="user_info_endpoint" name="userInfoEndpoint" type="text">
					</div>
					<div class="mb-2">
						<label class="form-label" for="scope">Scope</label>
						<input class="form-control" data-trim="true" id="scope" name="scope" type="text">
					</div>
					<div class="mb-2">
						<label class="form-label" for="email_claim">Email claim</label>
						<input class="form-control" data-trim="true" id="email_claim" name="emailClaim" type="text" value="email">
					</div>
					<div class="mb-2">
						<label class="form-label" for="roles_claim">Roles claim</label>
						<input class="form-control" data-trim="true" id="roles_claim" name="rolesClaim" type="text">
					</div>
				</form>
				<div class="d-flex mt-3 small">
					<div class="me-2" style="width: 32px;">
						<img src="https://fusionauth.io/img/favicon.png" alt="FusionAuth" class="w-100">
					</div>
					<div>
						Forked from <a href="https://fusionauth.io">FusionAuth</a> <br>
						<a href="https://github.com/FusionAuth/nodebb-plugin-fusionauth-oidc" target="_blank"
						   rel="noopener">
							https://github.com/FusionAuth/nodebb-plugin-fusionauth-oidc
						</a>
					</div>
					<button class="btn btn-primary btn-sm fw-semibold ff-secondary text-center text-nowrap align-self-center ms-auto"
							id="fusionauth-oidc-save">Save</button>
				</div>
			</div>
		</div>
	</div>
</div>
