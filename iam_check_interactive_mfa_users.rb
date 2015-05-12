//
// iam_check_interactive_mfa_users.rb - John Martinez (john@evident.io)
// PROVIDED AS IS WITH NO WARRANTY OR GUARANTEES
//
// Description:
// This check returns a fail if an interactive IAM user (a user with a password set)
// does not have an MFA device assigned.
//

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

