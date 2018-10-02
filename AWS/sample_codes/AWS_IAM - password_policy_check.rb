#
# Copyright (c) 2013, 2014, 2015, 2016, 2017, 2018. Evident.io (Evident). All Rights Reserved. 
#   Evident.io shall retain all ownership of all right, title and interest in and to 
#   the Licensed Software, Documentation, Source Code, Object Code, and API's ("Deliverables"), 
#   including (a) all information and technology capable of general application to Evident.io's customers; 
#   and (b) any works created by Evident.io prior to its commencement of any Services for Customer. 
#
# Upon receipt of all fees, expenses and taxes due in respect of the relevant Services, 
#   Evident.io grants the Customer a perpetual, royalty-free, non-transferable, license to 
#   use, copy, configure and translate any Deliverable solely for internal business operations of the Customer 
#   as they relate to the Evident.io platform and products, 
#   and always subject to Evident.io's underlying intellectual property rights.
#
# IN NO EVENT SHALL EVIDENT.IO BE LIABLE TO ANY PARTY FOR DIRECT, INDIRECT, SPECIAL, 
#   INCIDENTAL, OR CONSEQUENTIAL DAMAGES, INCLUDING LOST PROFITS, ARISING OUT OF 
#   THE USE OF THIS SOFTWARE AND ITS DOCUMENTATION, 
#   EVEN IF EVIDENT.IO HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# EVIDENT.IO SPECIFICALLY DISCLAIMS ANY WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
#  THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. 
#  THE SOFTWARE AND ACCOMPANYING DOCUMENTATION, IF ANY, PROVIDED HEREUNDER IS PROVIDED "AS IS". 
#  EVIDENT.IO HAS NO OBLIGATION TO PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR MODIFICATIONS.
#

#
# Description:
# A custom signature version of AWS:IAM-002 (Password Policy)
# If you use this signature, it is recommended that you suppress AWS:IAM-002
# 
# Default Conditions:
# - PASS: Password policy matches all conditions listed in 'config' section
# - FAIL: Password policy doesn't match
#
# Resolution/Remediation:
# 1. Log into your AWS console.
# 2. Go to the IAM service.
# 3. On the left menu, click Account Settings and expand the Password Policy option.
# 4. The best security practice is to enforce a strong password policy, including the following:
#     - Enter Minimum password length, which should be at least 14
#     - elect Require at least one uppercase letter
#     - Select Require at least one lowercase letter
#     - Select Require one number
#     - Select Require at least one non-alphanumeric character
#     - Select Allow users to change their own password
#     - Select Enable password expiration and set the expiration period to 90 days.
#     - Select Prevent password reuse and set the number of passwords to remember to 1
# 5. Click Apply password policy.
#

#    ______     ___     ____  _____   ________   _____     ______   
#  .' ___  |  .'   `.  |_   \|_   _| |_   __  | |_   _|  .' ___  |  
# / .'   \_| /  .-.  \   |   \ | |     | |_ \_|   | |   / .'   \_|  
# | |        | |   | |   | |\ \| |     |  _|      | |   | |   ____  
# \ `.___.'\ \  `-'  /  _| |_\   |_   _| |_      _| |_  \ `.___]  | 
#  `.____ .'  `.___.'  |_____|\____| |_____|    |_____|  `._____.'  
# Configurable options                                                                  
@options = {  
  minimum_password_length: 14,
  require_symbols: true,
  require_numbers: true,
  require_uppercase_characters: true,
  require_lowercase_characters: true,
  allow_users_to_change_password: true,
  max_password_age: 90,
  password_reuse_prevention: 1
}

#    ______   ____  ____   ________     ______   ___  ____     ______   
#  .' ___  | |_   ||   _| |_   __  |  .' ___  | |_  ||_  _|  .' ____ \  
# / .'   \_|   | |__| |     | |_ \_| / .'   \_|   | |_/ /    | (___ \_| 
# | |          |  __  |     |  _| _  | |          |  __'.     _.____`.  
# \ `.___.'\  _| |  | |_   _| |__/ | \ `.___.'\  _| |  \ \_  | \____) | 
#  `.____ .' |____||____| |________|  `.____ .' |____||____|  \______.' 
                                                                      
# deep inspection attribute will be included in each alert
configure do |c|
  c.valid_regions     = [:us_east_1]
  c.display_as        = :global
  c.deep_inspection   = [:minimum_password_length, :require_symbols,
                         :require_numbers, :require_uppercase_characters,
                         :require_lowercase_characters, :allow_users_to_change_password,
                         :max_password_age, :password_reuse_prevention]
end


def perform(aws)
  begin
    password_policy = aws.iam.get_account_password_policy[:password_policy]

    set_data(password_policy)
    if valid_password_policy?(password_policy)
      pass(message: "The password policy satisfies the enforced policy.", enforced_policy: @options)
    else
      fail(message: "The password policy does not meet the enforced policy", enforced_policy: @options)
    end

  rescue StandardError => e
    if (e.message.include? "cannot be found")
      fail(message: 'No password policy is presently available for this account.') 
    else
      fail(errors: e.message)
    end
  end
end



def valid_password_policy?(password_policy)
  @options.each do | key, val |
    return false if password_policy[key].nil?
  end

  password_policy[:minimum_password_length] >= @options[:minimum_password_length] &&
  (@options[:require_symbols] == false ||
  password_policy[:require_symbols] == @options[:require_symbols]) &&
  (@options[:require_numbers] == false ||
  password_policy[:require_numbers] == @options[:require_numbers]) &&
  (@options[:require_uppercase_characters] == false ||
  password_policy[:require_uppercase_characters] == @options[:require_uppercase_characters]) &&
  (@options[:require_lowercase_characters] == false ||
  password_policy[:require_lowercase_characters] == @options[:require_lowercase_characters]) &&
  (@options[:allow_users_to_change_password] == false ||
  password_policy[:allow_users_to_change_password] == @options[:allow_users_to_change_password]) &&
  password_policy[:max_password_age] <= @options[:max_password_age] &&
  password_policy[:password_reuse_prevention] >= @options[:password_reuse_prevention]
end
