## 
## rds_public_access.rb: Check for Public Access to RDS DB
##
## PROVIDED AS IS WITH NO WARRANTY OR GUARANTEES
## Copyright (c) 2016 Evident.io, Inc., All Rights Reserved
##
## Description:
## Public Access to RDS can be granted, but in almost all cases should not due to risk
## in exposing sensitive data.
## 
## Remediation:
## To disable Public Access to your RDS DB log into your AWS Console and
##
##      -Select "RDS" from the services list.
##      -Select "Instances" in the left menu, then select the database instance you wish to configure.
##      -From the "Instance Actions" menu, select "Modify".
##       -Scroll down to "Publicly Accessible", and set to "False".
##      -Click "Continue", and you are done!
##

configure do |c|
    c.deep_inspection   = [:db_name, :db_instance_identifier, :publicly_accessible]
end

# Required perform method
def perform(aws)
	rds = aws.rds.describe_db_instances.db_instances
	rds.each do |db|
		db_name = db.db_name
		if db_name == nil
            rds_name = db_instance_identifier
        else
            rds_name = db_name
        end
        
        publicly_accessible = db.publicly_accessible
        
		if publicly_accessible == true
           fail(message: "RDS #{rds_name} is Publicly accessible", resource_id: rds_name)
        else
           pass(message: "RDS #{rds_name}  is private", resource_id: rds_name)
       end               
    end
end
