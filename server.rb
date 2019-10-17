#!/usr/bin/env ruby

# Copyright (C) 2019 Authlete, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific
# language governing permissions and limitations under the
# License.

# This authorization server implementation is useless for production environment
# due to the following reasons and other unwritten ones.
#
# - PKCE (RFC 7636), a must security feature, is not supported.
# - Other flows than the authorization code flow are not supported.
# - Confidential clients are not supported. Note that this implies that this
#   implementation does not have any code related to client authentication.
# - The 'redirect_uri' request parameter must always be given although RFC 6749
#   allows omission of the parameter in some cases.
# - RFC 6749 allows redirect URIs to include a query part, but this implementation
#   fails to build a proper value for the Location header in the case.
# - It is not checked whether the same request parameters are not given although
#   RFC 6749 requires that "Request and response parameters MUST NOT be included
#   more than once."
# - This implementation does not strictly follow the requirement in RFC 6749:
#   "Parameters sent without a value MUST be treated as if they were omitted
#   from the request."
# - The authorization endpoint does not use '302 Found' in error cases even
#   after the redirect URI it should use has been determined.
# - The value of the 'state' request parameter is not checked although RFC 6749
#   requires that characters of 'state' be in the range of %x20-7E.
# - The token endpoint requires 'client_id' as a mandatory parameter because
#   it knows that all clients are 'public'.
# - The token endpoint requires 'redirect_uri' as a mandatory parameter because
#   (1) it knows that the authorization endpoint always requires 'redirect_uri'
#   and (2) it does not support other flows than the authorization code flow.
# - No mechanism to clean up expired authorization codes and access tokens
#   periodically.
# - Entropy of authorization codes and access tokens is too low.
# - The feature of sinatra's session is used without any security consideration.
# - No protection for CSRF.
# - The following are hard-coded.
#     * One client application
#     * One end-user account
#     * Access token duration

require 'json'
require 'securerandom'
require 'sinatra'

#--------------------------------------------------
# Sinatra Configuration
#--------------------------------------------------
configure do
    enable :sessions
end

#--------------------------------------------------
# Data Structures
#--------------------------------------------------

# Client Application
class Client
    attr_accessor :client_id
    attr_accessor :client_name
    attr_accessor :redirect_uris

    def initialize(client_id, client_name, redirect_uris)
        @client_id     = client_id
        @client_name   = client_name
        @redirect_uris = redirect_uris
    end
end

# User
class User
    attr_accessor :user_id
    attr_accessor :login_id
    attr_accessor :password

    def initialize(user_id, login_id, password)
        @user_id  = user_id
        @login_id = login_id
        @password = password
    end
end

# Authorization Code
class AuthorizationCode
    attr_accessor :value
    attr_accessor :user_id
    attr_accessor :client_id
    attr_accessor :scopes
    attr_accessor :redirect_uri
    attr_accessor :expires_at

    def initialize(user_id, client_id, scopes, redirect_uri, expires_at)
        @value        = SecureRandom.urlsafe_base64(6)
        @user_id      = user_id
        @client_id    = client_id
        @scopes       = scopes
        @redirect_uri = redirect_uri
        @expires_at   = expires_at
    end
end

# Access Token
class AccessToken
    attr_accessor :value
    attr_accessor :user_id
    attr_accessor :client_id
    attr_accessor :scopes
    attr_accessor :expires_at

    def initialize(user_id, client_id, scopes, expires_at)
        @value      = SecureRandom.urlsafe_base64(6)
        @user_id    = user_id
        @client_id  = client_id
        @scopes     = scopes
        @expires_at = expires_at
    end
end

#--------------------------------------------------
# Data Stores
#--------------------------------------------------

# Registered Client Applications
$ClientStore = [
    # Client ID, Client Name, Redirect URIs
    Client.new('1', 'My Client', ['http://example.com/'])
]

# Registered Users
$UserStore = [
    # User ID, Login ID, Password
    User.new('1', 'john', 'john')
]

# Issued Authorization Codes
# Keys are AuthorizationCode.value, values are AuthorizationCode instances.
$AuthorizationCodeStore = {}

# Issued Access Tokens
# Keys are AccessToken.value, values are AccessToken instances.
$AccessTokenStore = {}

#--------------------------------------------------
# Constants
#--------------------------------------------------

$SUPPORTED_SCOPES            = %w(read write)
$AUTHORIZATION_CODE_DURATION = 600
$ACCESS_TOKEN_DURATION       = 86400

#--------------------------------------------------
# Endpoints
#--------------------------------------------------

# Authorization Endpoint
get '/authorization' do
    # --- client_id ---
    # Look up a client by the 'client_id' request parameter.
    client = look_up_client(params['client_id'])
    if client.nil?
        halt 400, 'client_id is wrong.'
    end

    # --- redirect_uri ---
    # This implementation always requires the 'redirect_uri' request parameter.
    redirect_uri = params['redirect_uri']
    if redirect_uri.nil? || !client.redirect_uris.include?(redirect_uri)
        halt 400, 'redirect_uri is wrong.'
    end

    # --- response_type ---
    # Supports the authorization code flow only.
    if params['response_type'] != 'code'
        halt 400, 'response_type is wrong.'
    end

    # --- state ---
    state = params['state'].nil? ? '' : params['state']

    # --- scope ---
    # Filter supported scopes.
    scopes = filter_scopes(params['scope'])

    # Put some parameters into the session for later use.
    session[:client]       = client
    session[:state]        = state
    session[:scopes]       = scopes
    session[:redirect_uri] = redirect_uri

    # Render the authorization page.
    erb :authorization_page, :locals => {
        'client_name' => client.client_name,
        'scopes'      => scopes
    }
end

def look_up_client(value)
    $ClientStore.find { |client| client.client_id == value }
end

def filter_scopes(value)
    return [] if value.nil?
    scopes = value.split(/\s+/)
    scopes.find_all { |scope| $SUPPORTED_SCOPES.include?(scope) }
end

# Decision Endpoint
post '/decision' do
    client       = session[:client]
    state        = session[:state]
    scopes       = session[:scopes]
    redirect_uri = session[:redirect_uri]
    session.clear

    # The response will be returned to the location pointed to by
    # the redirect URI with the 'state'.
    location = "#{redirect_uri}?state=#{state}"

    # If the 'Approve' button was not pressed.
    if params['approved'] != 'true'
        redirect location + '&error=access_denied' +
          '&error_description=The+request+was+not+approved.', 302
    end

    # Look up a user by the login ID and the password.
    user = find_user(params['login_id'], params['password'])
    if user.nil?
        redirect location + '&error=access_denied' +
          '&error_description=End-user+authentication+failed.', 302
    end

    # Generate an authorization code and save it to the store.
    expires_at = Time.now.to_i + $AUTHORIZATION_CODE_DURATION
    code = AuthorizationCode.new(
        user.user_id, client.client_id, scopes, redirect_uri, expires_at)
    $AuthorizationCodeStore[code.value] = code

    # Successful response with the authorization code.
    redirect location + '&code=' + code.value, 302
end

def find_user(login_id, password)
    $UserStore.find do |user|
        user.login_id == login_id && user.password == password
    end
end

# Token Endpoint
post '/token' do
    content_type :json

    # --- grant_type ---
    # Supports the authorization code flow only.
    grant_type_value = extract_mandatory_parameter(params, 'grant_type')
    if grant_type_value != 'authorization_code'
        halt 400, {'error'=>'unsupported_grant_type'}.to_json
    end

    # --- code ---
    # In the authorization code flow, the 'code' parameter is mandatory.
    code_value = extract_mandatory_parameter(params, 'code')
    code = $AuthorizationCodeStore[code_value]
    if code.nil?
        halt 400, {'error'=>'invalid_grant','error_description'=>
                   'The authorization code is not found.'}.to_json
    end
    if code.expires_at < Time.now.to_i
        $AuthorizationCodeStore.delete(code_value)
        halt 400, {'error'=>'invalid_grant','error_description'=>
                   'The authorization code has expired.'}.to_json
    end

    # --- redirect_uri --
    # If the corresponding authorization request included the 'redirect_uri'
    # parameter, the token request also must include the 'redirect_uri'
    # parameter. This implementation rejects all authorization requests that
    # don't include the 'redirect_uri' parameter.
    redirect_uri_value = extract_mandatory_parameter(params, 'redirect_uri')
    if redirect_uri_value != code.redirect_uri
        halt 400, {'error'=>'invalid_grant','error_description'=>
                   'redirect_uri is wrong.'}.to_json
    end

    # --- client_id ---
    # The 'client_id' parameter is mandatory unless the client type is
    # confidential and the client authentication method does not need the
    # 'client_id' parameter.
    client_id_value = extract_mandatory_parameter(params, 'client_id')
    if client_id_value != code.client_id
        halt 400, {'error'=>'invalid_grant','error_description'=>
                   'client_id is wrong.'}.to_json
    end

    # Generate an access token and save it to the store.
    expires_at = Time.now.to_i + $ACCESS_TOKEN_DURATION
    token = AccessToken.new(
        code.user_id, code.client_id, code.scopes, expires_at)
    $AccessTokenStore[token.value] = token

    # Remove the used authorization code.
    $AuthorizationCodeStore.delete(code_value)

    # Successful response with the access token.
    {
        'access_token' => token.value,
        'token_type'   => 'Bearer',
        'expires_in'   => $ACCESS_TOKEN_DURATION,
        'scope'        => token.scopes.join(' ')
    }.to_json
end

def extract_mandatory_parameter(params, key)
    value = params[key]

    if value.nil? || value == ''
        halt 400, {'error'=>'invalid_request','error_description'=>
                   "#{key} is missing."}.to_json
    end

    return value
end


#--------------------------------------------------
# UI Templates
#--------------------------------------------------
__END__
@@ authorization_page
<html>
<head>
  <title>Authorization Page</title>
</head>
<body class="font">
  <h2>Client Application</h2>
    <%= client_name %>

  <h2>Requested Permissions</h2>
    <% if scopes != nil %>
    <ol>
      <% scopes.each do |scope| %>
      <li><%= scope %></li>
      <% end %>
    </ol>
    <% end %>

  <h2>Approve?</h2>
    <form method="post" action="/decision">
      <input  type="text"     name="login_id" placeholder="Login ID"><br>
      <input  type="password" name="password" placeholder="Password"><br>
      <button type="submit" name="approved" value="true">Approve</button>
      <button type="submit" name="denied"   value="true">Deny</button>
    </form>
  </body>
</html>
