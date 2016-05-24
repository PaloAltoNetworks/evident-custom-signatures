##
## iam_password_policy_check.rb - John Robel (robel@evident.io)
## PROVIDED AS IS WITH NO WARRANTY OR GUARANTEES
##
## Description:
## This check returns a fail if the password policy is not set to include ALL
## options enabled and a 14 character password length.  This is a modification
## to a built in signature and provided as an example.  In the paid version of 
## the platform, this is a copyable signature AWS:IAM-002
##
## If you choose to use this signature, it is recomended that you supress
## AWS:IAM-002 since they are checking the same policy just with different 
## options.
##

configure do |c|
  c.valid_regions     = [:us_east_1]
  c.display_as        = :global
  c.deep_inspection   = [:minimum_password_length, :require_symbols,
                         :require_numbers, :require_uppercase_characters,
                         :require_lowercase_characters, :allow_users_to_change_password,
                         :max_password_age, :password_reuse_prevention]
end

def perform(aws)
  password_policy = aws.iam.get_account_password_policy[:password_policy]
  return fail(condition: 'No password policy is presently available for this account.') if password_policy.blank?
  set_data(password_policy)
  if valid_password_policy?(password_policy)
    pass(condition: 'min_length >=14 and require_symbols, require_numbers, require_uppercase_characters, require_lowercase_characters are true.')
  else
    fail
  end
rescue StandardError => e
  error(errors: e.message)
end

def valid_password_policy?(password_policy)
  password_policy[:minimum_password_length] >= 14 &&
    password_policy[:require_symbols] =true &&
    password_policy[:require_numbers] =true &&
    password_policy[:require_uppercase_characters] =true &&
    password_policy[:require_lowercase_characters] =true &&
    password_policy[:allow_users_to_change_password] =true &&
    password_policy[:max_password_age] >=90 &&
    password_policy[:password_reuse_prevention] >= 5 
end
