require 'base64'
require 'digest/sha1'

#
# secure_sessions.rb
#
class SecureSessions
  cattr_accessor :secret
  attr_accessor :controller, :secure_session

  # credential enforcer factory class method
  def self.factory(ctrl, ss, ckys)
    # in future this will be more configurable, but for now it's the most needed use-case
    pw = SecureSessions::Password.new(ctrl, ss)
    # cky = SecureSessions::Cookie.new(ctrl, ss)
    scky = SecureSessions::SslCookie.new(ctrl, ss, ckys)
    # our sessions use primarily secure cookies, but have a password prerequisite at login
    SecureSessions::Composite.new(
      :primary => scky,
      :required => pw
    )
  end


  ##
  ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ##
  ## Controller submodule to be mixed-in to ActionController::Base
  ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ##
  ##

  module Controller
    # mix-in class methods
    def self.included(base)
      base.extend(ClassMethods)
    end

    ## all mixed-in methods are protected, and should never become actions
    protected

    # secure session hash, just a named subhash of controller's session
    def secure_session
      session[:secure] ||= {}
    end

    # stack of previous requests
    def uri_stack
      secure_session[:uri_stack] ||= []
    end

    # attempt to authenticate user and authorize a request
    def authenticate
      # instantiate the credential object
      enforcer = SecureSessions.factory(self, secure_session, cookies)

      # essentially, check the session cache first # FIXME n-check this, n >= 2
      return true if enforcer.authenticated?

      # attempt to validate credentials
      return true if enforcer.validate

      # at this point, the required credentials are absent, so "push stack", i.e.:
      #   * save the request
      #   * follow the credential object's fail_to argument
      uri_stack << request.request_uri
      flash[:notice] = enforcer.follow_message if enforcer.follow_message
      redirect_to(enforcer.fail_to)
    end

    # the equivalent of "pop stack"
    def return_from_authentication
      enforcer = SecureSessions.factory(self, secure_session, cookies)
      # upon return, attempt to issue credentials, which will:
      #   * attempt to validate any subordinate credential, like a password,
      #   * upon success, issue the object credential, like a cookie
      #   * then retrace our steps to the original request
      if enforcer.issue 
        follow_uri = uri_stack.shift
        redirect_to(follow_uri) if follow_uri
        redirect_to(enforcer.default_to)
        return
      end
      flash[:notice] = enforcer.fail_message if enforcer.fail_message 
      redirect_to(enforcer.fail_to)
    end


    ## had the user logged in (over SSL)
    def logged_in?
      # Note: one of few cases where we bypass secure_session protection
      session[:secure] ||= {}
      session[:secure].has_key?(:uid)
    end
    
    # place request.post? && return_from_authentication switch into before filters
    def validate_credentials
      if request.post?
        # return_from_authentication and return
        return_from_authentication
      end
    end

    # placed into before filters, calls cred.delete, etc. 
    def delete_credentials
      enforcer = SecureSessions.factory(self, secure_session, cookies)
      enforcer.delete
      reset_session
      flash[:notice] = "You have successfully logged out."
      redirect_to(enforcer.logout_to)
    end
 
    # controller class methods
    module ClassMethods
      # define an action as a fill-in form, such as a login form or 2-factor input page
      def secure_login(action)
        before_filter :validate_credentials, :only => action
      end
      # define a logout action
      def secure_logout(action)
        before_filter :delete_credentials, :only => action
      end
    end

  end


  ##
  ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ##
  ## session enforcement code: token class, credential classes and subclasses
  ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ##
  ##

  #
  # a token is a raw credential string, to be used as a cookie, url param, etc.
  #
  class Token
    attr_accessor :raw_token, :qop, :uid, :timestamp

    # construct from either raw token or validation params
    def initialize(creds_or_raw_token)
      if creds_or_raw_token.class == Hash
          @qop = creds_or_raw_token[:qop]
          @uid = creds_or_raw_token[:uid]
          @timestamp = creds_or_raw_token[:timestamp]
      else 
          @raw_token = creds_or_raw_token
      end
    end

    # generate raw token value
    def generate
      mac(qop, uid, timestamp)
    end
 
    # validate the token against expected parameters 
    def validate(args)
      raw_token == mac(args[:qop], args[:uid], args[:timestamp])
    end

    private 

    # message authentication code (does this need HMAC?, doubt it)
    def mac(qop, uid, timestamp)
      hash_arg = "#{qop}#{SecureSessions.secret}#{uid},#{timestamp}"
      Base64.encode64(Digest::SHA1.digest(hash_arg)).gsub(/=/, '').chomp
    end
  end


  #
  # common code, template methods for credential objects
  # 

  # identify subject with the provided user ID
  def identify(uid)
    secure_session[:uid] = uid
    secure_session[:timestamp] = Time.now.to_i
  end
  # return ID
  def identity
    return secure_session[:uid] if identified?
    raise "Secure Sessions Plugin: User identity unknown at the time it was required."
  end
  # has the session been previously identified
  def identified?
    secure_session.has_key?(:uid)
  end
  # overridden to provide strongest proof of ID (like checking a secure cookie)
  def authenticated? 
    identified?  
  end
  # timestamp
  def timestamp
    return secure_session[:timestamp] if identified?
    raise "Secure Sessions Plugin: User identity unknown at the time it was required."
  end
  # issue credentials, usually overridden
  def issue; end
  # validate credentials, always overridden
  def validate; false; end
  # remove and/or delete credentials, usually overridden
  def delete; end

  #
  # plaintext cookie credential, and base class for secure cookie
  #
  class Cookie < ::SecureSessions
    attr_accessor :cookies
    cattr_accessor :key, :domain, :delete_to, :http_only, :logout_to

    def initialize(ctrl, ss, ckys)
      self.controller = ctrl
      self.secure_session = ss
      self.cookies = ckys
    end

    def issue
      # compute token value
      token_value = SecureSessions::Token.new(
        :qop => ssl_only_cookie? ? 1 : 0,
        :uid => identity,
        :timestamp => timestamp
      ).generate
      # form set-cookie header with appropriate property values
      cookies[cky_key] = {
        :value => token_value,
        :domain => SecureSessions::Cookie.domain,
        :secure => ssl_only_cookie?,
        # Note: http_only defaults to true: just the opposite of the RoR API
        :http_only => SecureSessions::Cookie.http_only.nil? ? true : SecureSessions::Cookie.http_only
      }
      # cache this cookie for fast(er) verification
      secure_session[cky_key] = token_value
    end
    # extract the strongest cookie from the request, and validate it
    def validate
      token = SecureSessions::Token.new(cookies[cky_key])
      token.validate(
        :qop => ssl_only_cookie? ? 1 : 0,
        :uid => identity, 
        :timestamp => timestamp
      )
    end
    def delete
      # cookies.delete cky_key won't work here 
      # browser won't respect defaults so we must "issue" an empty cookie w/ matching params
      cookies[cky_key] = {
        :value => '',
        # :expires => 'Thu, 01 Jan 1970 00:00:00 GMT',
        # :expires => Time.now - 1.year,
        :expires => Time.now - Time.now.to_i.seconds,
        :domain => SecureSessions::Cookie.domain,
        :secure => ssl_only_cookie?
      }
    end

    # override authenticated? to invoke the strongest possible proof of ID
    def authenticated?
      # extract strongest cookie and check against cache
      cookies[cky_key] == secure_session[cky_key]
    end

    protected
    def ssl_only_cookie?; false; end
    def cky_key
      k = SecureSessions::Cookie.key
      level = ssl_only_cookie? ? 1 : 0
      "#{k}_#{level}".to_sym
    end
  end
  #
  # SSL-only cookie credential
  #
  class SslCookie < ::SecureSessions::Cookie
    protected
    def ssl_only_cookie?; true; end
  end
  #
  # password-based credential
  #
  class Password < ::SecureSessions
    cattr_accessor :validate_proc, :fail_to, :default_to

    def initialize(ctrl, ss)
      self.controller = ctrl 
      self.secure_session = ss
    end

    # simply chain to the user-supplied verification Proc
    def validate
      return false unless (uid = validate_proc.call(controller))
      identify(uid)
    end

    def follow_message; 'Please Log in First.'; end
    def fail_message; 'Username and/or Password incorrect.'; end
  end
  #
  # composite credential, using the required credential to issue the primary credential 
  #
  class Composite < ::SecureSessions
    attr_accessor :primary, :required
    def initialize(args)
      self.primary = args[:primary]
      self.required = args[:required]
      self.controller = primary.controller
      self.secure_session = primary.secure_session
    end
    def issue
      if required.validate
        primary.issue
      else
        false
      end
    end
    # chain to primary
    def validate; primary.validate; end
    def delete; primary.delete; end
    def authenticated?; identified? && primary.authenticated?; end
    def logout_to; primary.logout_to; end

    # chain to required
    def fail_to; required.fail_to; end
    def fail_message; required.fail_message; end
    def follow_message; required.follow_message; end
    def default_to; required.default_to; end
    
  end
end
