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
# Ensure RDS Databases are not Publicly available.
# 
# Public Access to RDS can be granted, but in almost all cases should not due to risk
# in exposing sensitive data.
# 
# Remediation:
#
# To disable Public Access to your RDS DB log into your AWS Console
#
# - Select "RDS" from the services list.
# - Select "Instances" in the left menu, then select the database instance you wish to configure.
# - From the "Instance Actions" menu, select "Modify".
# - Scroll down to "Publicly Accessible", and set to "False".
# - Click "Continue", and you are done!
#

#    ______   ____  ____   ________     ______   ___  ____     ______   
#  .' ___  | |_   ||   _| |_   __  |  .' ___  | |_  ||_  _|  .' ____ \  
# / .'   \_|   | |__| |     | |_ \_| / .'   \_|   | |_/ /    | (___ \_| 
# | |          |  __  |     |  _| _  | |          |  __'.     _.____`.  
# \ `.___.'\  _| |  | |_   _| |__/ | \ `.___.'\  _| |  \ \_  | \____) | 
#  `.____ .' |____||____| |________|  `.____ .' |____||____|  \______.' 
#

configure do |c|
  c.deep_inspection = [:db_name, :db_instance_identifier, :publicly_accessible, :region]
end

def perform(aws)

  rds    = aws.rds.describe_db_instances.db_instances
  region = aws.region

  rds.each do | db |
    db_name  = db.db_name
    rds_name = db.db_instance_identifier
        
    publicly_accessible = db.publicly_accessible
    set_data(db_name: db_name, db_instance_identifier: rds_name, publicly_accessible: publicly_accessible, region: region)
        
    if publicly_accessible == true
      fail(message: "RDS #{rds_name} is Publicly accessible.", resource_id: rds_name)
    else
      pass(message: "RDS #{rds_name} is not Publicly accessible.", resource_id: rds_name)
    end               
  end
end
