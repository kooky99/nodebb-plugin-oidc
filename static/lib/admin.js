'use strict';

import {save, load} from 'settings';
import {alert} from 'alerts';

const updateField = function (selector, value) {
  if (!value) {
    return;
  }

  const element = $(selector);
  if (!element.val()) {
    element.val(value);
  }
};

export function init() {
  load('fusionauth-oidc', $('#fusionauth-oidc-settings'));

  const saveForm = function (form) {
    save('fusionauth-oidc', form, function () {
      alert({
        type: 'success',
        alert_id: 'sso-oidc-saved',
        title: 'Settings Saved',
        message: 'If you changed the email claim, you will need to restart before it will be applied.',
        clickfn: function () {
          socket.emit('admin.reload');
        },
      });
    });
  };

  $('#fusionauth-oidc-save').on('click', function () {
    const form = $('#fusionauth-oidc-settings');

    // Trim the fields
    form.find('input[data-trim="true"]').each(function () {
      $(this).val($.trim($(this).val()));
    });

    const baseURL = $('input[name="discoveryBaseURL"]').val();
    if (!baseURL) {
      saveForm(form);
      return;
    }

    fetch(baseURL + '/.well-known/openid-configuration')
      .then((res) => res.json())
      .then((json) => {
        updateField('input[name="authorizationEndpoint"]', json.authorization_endpoint);
        updateField('input[name="tokenEndpoint"]', json.token_endpoint);
        updateField('input[name="userInfoEndpoint"]', json.userinfo_endpoint);
        //updateField('input[name="logoutEndpoint"]', json.end_session_endpoint);
        saveForm(form);
      })
      .catch((e) => {
        console.error(e);
        alert({
          type: 'error',
          alert_id: 'sso-oidc-error',
          title: 'An error occurred',
          message: 'An error has occurred while trying to discover the OIDC configuration. Make sure that this platform supports the well known configuration URL and that you have the right URL.',
        });
      });
  });
}
