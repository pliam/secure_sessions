require 'secure_sessions'

# mix-in our controller instance and class methods 
ActionController::Base.class_eval do
  include SecureSessions::Controller
end
