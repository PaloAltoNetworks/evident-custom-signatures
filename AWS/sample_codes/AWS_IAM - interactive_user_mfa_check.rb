# Copyright (c) 2013, 2014, 2015, 2016, 2017, 2018. Evident.io (Evident). All Rights Reserved. 
# 
#   Evident.io shall retain all ownership of all right, title and interest in and to 
#   the Licensed Software, Documentation, Source Code, Object Code, and API's ("Deliverables"), 
#   including (a) all information and technology capable of general application to Evident.io's
#   customers; and (b) any works created by Evident.io prior to its commencement of any
#   Services for Customer.
# 
# Upon receipt of all fees, expenses and taxes due in respect of the relevant Services, 
#   Evident.io grants the Customer a perpetual, royalty-free, non-transferable, license to 
#   use, copy, configure and translate any Deliverable solely for internal business operations
#   of the Customer as they relate to the Evident.io platform and products, and always
#   subject to Evident.io's underlying intellectual property rights.
# 
# IN NO EVENT SHALL EVIDENT.IO BE LIABLE TO ANY PARTY FOR DIRECT, INDIRECT, SPECIAL, 
#   INCIDENTAL, OR CONSEQUENTIAL DAMAGES, INCLUDING LOST PROFITS, ARISING OUT OF 
#   THE USE OF THIS SOFTWARE AND ITS DOCUMENTATION, EVEN IF EVIDENT.IO HAS BEEN HAS BEEN
#   ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
# 
# EVIDENT.IO SPECIFICALLY DISCLAIMS ANY WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
#   THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. 
#   THE SOFTWARE AND ACCOMPANYING DOCUMENTATION, IF ANY, PROVIDED HEREUNDER IS PROVIDED "AS IS". 
#   EVIDENT.IO HAS NO OBLIGATION TO PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS,
#   OR MODIFICATIONS.
#
# Description:
#
# Ensure that Multi-Factor Authentication (MFA) is enabled for all IAM users.
#
# Default Conditions:
#
# - PASS: IAM User has a MFA device enabled
# - WARN: IAM User is NOT an interactive user nor has a MFA device enabled
# - FAIL: IAM User is an interactive user and does not have a MFA device enabled
#
# Remediation:
#
# https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa.html
#

#    ______   ____  ____   ________     ______   ___  ____     ______   
#  .' ___  | |_   ||   _| |_   __  |  .' ___  | |_  ||_  _|  .' ____ \  
# / .'   \_|   | |__| |     | |_ \_| / .'   \_|   | |_/ /    | (___ \_| 
# | |          |  __  |     |  _| _  | |          |  __'.     _.____`.  
# \ `.___.'\  _| |  | |_   _| |__/ | \ `.___.'\  _| |  \ \_  | \____) | 
#  `.____ .' |____||____| |________|  `.____ .' |____||____|  \______.' 
#

configure do |c|
  c.valid_regions   = [:us_east_1]
  c.display_as      = :global
  c.deep_inspection = [:username, :login_profile, :mfa_devices]
end

def perform(aws)
    
  users = aws.iam.list_users()[:users]

  users.each do | user |
    username = user[:user_name]

    begin
      login_profile = aws.iam.get_login_profile(user_name: username)
    rescue StandardError => e
      login_profile = nil
    end
    
    mfa_devices = aws.iam.list_mfa_devices(user_name: username)[:mfa_devices]
            
    set_data(username: username, login_profile: login_profile, mfa_devices: mfa_devices)

    if mfa_devices.empty? && login_profile.nil?
      warn(message: "User #{username} is not an interactive user nor has a MFA device enabled.", resource_id: username)
    elsif mfa_devices.empty?
      fail(message: "User #{username} is an interactive user and does not have a MFA device enabled.", resource_id: username)
    else
      pass(message: "User #{username} has a MFA device enabled.", resource_id: username)
    end
            
  end
end
