# Tutorial - Creating Azure Custom Signature (Ruby)

## Anatomy of a custom signature
Let's take a look at a simple custom signature:

```ruby
def perform(azure)
  azure.compute.virtual_machines.list_all.each do |resource|
    fail(message: "My Alert Message", resource: resource )
  end
end
```

The following custom signature will produce the following alert(s):

```
     status:  fail
resource_id:  /subscriptions/abcdefab-abcd-1234-abcd-0000000f0000/resourceGroups/RGROUP-VM/providers/Microsoft.Compute/virtualMachines/myVM
     Region:  eastus
   metadata:  {
                "message"         => "My Alert Message",
                "deep_inspection" => {}
              }

```

---


#### Perform Section (Required)

The **perform** section is the main section of the custom signature. Evident invokes **peform** and executes your code.

Notice the **azure** parameter in `def perform(azure)`. This is the azure client created by Evident which allows you to make API calls. For the list of supported services, please refer to [this readme](../README.md).
<br>For the list of available service-specific methods, please refer to [Azure Ruby SDK](https://github.com/Azure/azure-sdk-for-ruby)


#### Available Alerts
Alerts can be triggered anywhere in the custom signature. The following alerts can be triggered:
- `pass(attr1: attr1_value, attr2: attr2_value, ... )`
- `warn(attr1: attr1_value, attr2: attr2_value, ... )`
- `fail(attr1: attr1_value, attr2: attr2_value, ... )`
- `info(attr1: attr1_value, attr2: attr2_value, ... )`

You can pass as many key-value parameter as possible. These parameters shows up in the alert as attributes. 

<br>
:warning: When you trigger/generate an alert, you will need to have `resource_id` and `region` attributes set. You can set them in few ways:

**1. Using Azure resource object.** Example:

```ruby
def perform(azure)
  azure.compute.virtual_machines.list_all.each do |resource|
    fail(message: "My Alert Message", resource: resource )
  end
end
```

When you pass in Azure resource object to `resource` parameter, custom signature worker process will try to extract `id` and `region` from the resource object.


**2. Manually Set resource object**

In some cases, the Azure resource object does not include `id` and `region` (it could be due to subscription-wide / global resource or other thing).
In that case, you can override the `region` requirement and manually set the `resource_id`. See **CONFIG (Optional)** section below for more information.


<br>
<br>

### CONFIG (Optional)

Adding the following config section will allow you to override the region to **global** and manually set the `resource_id`.
```
configure do |c|
  c.display_as = :global
end
```

For example, to analyze Azure Activity Log profile/export (one per subscription)

```ruby
# Overriding the region as 'global'
configure do |c|
  c.display_as = :global
end

def perform(azure)
  profile = azure.monitor.log_profiles.list.value
  # no export profile
  if profile.count < 1
    return
  else
    # as of 09/2018, you can only have one log profile per subscription
    profile = profile[0]
    
    retention_policy = profile.retention_policy.days
    
    pass(retention_policy: retention_policy, resource_id: "test")
  end
end

```

## TIPS

#### Setting alert attributes
Instead of this:
```ruby
def perform(azure)
  azure.compute.virtual_machines.list_all.each do |resource|
    fail(message: ("Fail for instance id:" + resource.id), resource: resource, os_profile: resource.os_profile, network_profile: resource.network_profile, diagnostics_profile: resource.diagnostics_profile, provisioning_state: resource.provisioning_state)
  end
end
```

You can also do this:
```ruby
def perform(azure)
  azure.compute.virtual_machines.list_all.each do |resource|
    alert_attr = {
      message: ("Fail for instance id:" + resource.id),
      os_profile: resource.os_profile,
      network_profile: resource.network_profile,
      diagnostics_profile: resource.diagnostics_profile,
      provisioning_state: resource.provisioning_state
    }

    fail(resource: resource, **alert_attr)
  end
end
```
