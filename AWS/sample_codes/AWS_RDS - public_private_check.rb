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
# rds_public_access.rb: 
#
# PROVIDED AS IS WITH NO WARRANTY OR GUARANTEES
# Copyright (c) 2017 Evident.io, Inc., All Rights Reserved
#
# Description:
# Check for Public Access to RDS DB
# 
# Public Access to RDS can be granted, but in almost all cases should not due to risk
# in exposing sensitive data.
# 
# Remediation:
# To disable Public Access to your RDS DB log into your AWS Console and
#
#      -Select "RDS" from the services list.
#      -Select "Instances" in the left menu, then select the database instance you wish to configure.
#      -From the "Instance Actions" menu, select "Modify".
#       -Scroll down to "Publicly Accessible", and set to "False".
#      -Click "Continue", and you are done!
#

configure do |c|
    c.deep_inspection   = [:db_name, :db_instance_identifier, :publicly_accessible]
    c.unique_identifier = [:rds_name]
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