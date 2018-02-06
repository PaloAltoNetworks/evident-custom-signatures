# Custom Signature Tutorial ( Ruby )

## `overview`
A custom signature is a function that reads [AWS SDK](http://docs.aws.amazon.com/sdkforruby/api/) data from Amazon, and creates one or more __alerts__ based on that data and conditionals you describe.  

An __alert__ has
* a status of `pass` `fail` `warn` `info` or `error`
* identifying metadata such as `instance_id` or `logging_status`
* This field is used to identify unique alerts that share the same signature but describe different AWS resources (ex. `volume_id` `instance_id` `bucket_name`)

* * *

A custom signature will always have two sections `config` and `perform`. An optional `options` section can also be used.

In the `config` section you define the parameters your signature will use when it runs. For example, you set which region you are interested in checking, and you give the signature a unique id.

In the `perform` section you write a function that implements your security policy, and creates one or more __alerts__.  The alerts are themselves are created using the `pass()` and `fail()` functions. Each __alert__ is then stored in the database.

In the `options` section you define settings to be used throughout the `perform` section. For example, a setting for the type of Volume storage to check for. 

## `options`

An example `options` section
```ruby
@options = {
  # Enter the type of Volume storage to check for
  # examples; "standard", "gp2"
  #
  type_to_check_for: "standard"
}
```

## `config`

An example `config` section
```ruby
configure do |c|
  c.valid_regions   = [:us_east_1]
  c.deep_inspection = [:volume_type, :volume_id]
end
```

`configure` is a function that is passed an anonymous callback function that receives a configuration object (here `c`) as the first argument.  Inside the anonymous function you have access to the configuration settings for the signature.

#### configuration metadata

##### `valid_regions`
* An array of regions to run the signature
* ex. `[:us_east_1, :us_west_2]`

##### `deep_inspection`
* An array of fields that provide additional information beyond the status when
an alert is viewed in the actual report.  
* These fields are referenced in the `perform` block when you call
`set_data()`

## `perform`

The `perform` section is a function that is passed the
 [AWS SDK](http://docs.aws.amazon.com/sdkforruby/api/) as an object.  You use
this `aws` object to make calls to AWS.  

Perform block psuedocode looks like
```ruby
def perform(aws)

    # make some AWS calls to get an array of resources
    # 
    # resources.each do | resource |
    #
    #     read some resource information using the aws object passed to the
    #     perform function
    # 
    #     store some of that resource information to the report using
    #     set_data()
    #
    #     compare it to a desired value or state
    #       call pass() or fail()
    #  
    # end

end
```

An example `perform` section with `options`:
```ruby
@options = {
  # Enter the type of Volume storage to check for
  # examples; "standard", "gp2"
  #
  type_to_check_for: "standard"
}

def perform(aws)

    region = aws.region

    # these are AWS SDK calls to get a list of resources to check
    volumes = aws.ec2.describe_volumes().volumes

    # this is our condition we are searching for in this signature
    # we want to enforce a specific volume type in this region
    # grab the desired storage_type from the options section
    storage_type = @options[:type_to_check_for]

    # for each volume returned from the AWS SDK call
    volumes.each do | volume |

        # this is where you specify the data for the fields listed in the
        # deep_inspection array
        volume_type = volume[:volume_type]
        volume_id   = volume[:volume_id]

        # call set_data() with each deep inspection object as the argument
        # will now have this additional information associated with it
        set_data(volume_type: volume_type, volume_id: volume_id, region: region)

        # our condition check
        # is the volume_type not the same as our desired type?
        if volume_type != storage_type

          # in this block the volume_type != storage_type
          # You will create a failed alert with a message.
          # The message is a string, and the failed alert is created by calling
          # fail( message: "some message indicating why", resource_id: resource_id)
          fail( message: "volume is not of type #{storage_type}", resource_id: volume_id)

        else

          # in this block the volume_type == storage_type
          # You will create a pass alert with a message.
          pass( message: "volume is of type #{storage_type}", resource_id: volume_id)

        end
    end
end
```

## `putting it all together`
```ruby
@options = {
  # Enter the type of Volume storage to check for
  # examples; "standard", "gp2"
  #
  type_to_check_for: "standard"
}

configure do |c|
  c.deep_inspection = [:volume_type, :volume_id, :region]
end

def perform(aws)

    region       = aws.region
    storage_type = @options[:type_to_check_for]

    volumes      = aws.ec2.describe_volumes().volumes

    volumes.each do | volume |
        volume_type = volume[:volume_type]
        volume_id   = volume[:volume_id]

        set_data(volume_type: volume_type, volume_id: volume_id, region: region)

        if volume_type != storage_type
          fail( message: "volume is not of type #{storage_type}", resource_id: volume_id)
        else
          pass( message: "volume is of type #{storage_type}", resource_id: volume_id)
        end
    end
end
```
