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
# This check returns a fail if an interactive IAM user (a user with a password set)
# does not have an MFA device assigned.
#
# John Martinez (john@evident.io)

configure do |c|
    c.deep_inspection   = [:user_name, :login_profile, :mfa_devices]
    c.unique_identifier = [:user_name]
end

def perform(aws)
    
    aws.iam.list_users.users.each do |user|    
    
        begin
        
            user_name = user[:user_name]
            login_profile = aws.iam.get_login_profile(user_name: user_name)
            mfa = aws.iam.list_mfa_devices(user_name: user_name)
            mfas = mfa.mfa_devices
            
            set_data(user_name: user_name, login_profile: login_profile, mfa_devices: mfas)

            if mfas.empty?
                fail(message: "User #{user_name} is an interactive user and does not have an MFA device enabled", resource_id: user_name)
            else
                pass(message: "User #{user_name} is an interactive user and has an MFA device enabled", resource_id: user_name)
            end
            
        rescue StandardError => e
        
            set_data(user_name: user_name, login_profile: login_profile, mfa_devices: mfas)
            pass(message: "User #{user_name} is a non-interactive user", resource_id: user_name)
            
        end
        
    end

end

