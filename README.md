# CloudGuard - IP Puller
## A script to pull IP address information from all assets where there is metadata within CloudGuard. 

The script writes to the output to a JSON file in the directory where you run it. All you need to set is the environment variables
for the value of your IP CloudGuard API keys. 

The output will be something similar to this:

```json
{
        "entityId": "eni-09484542c49b7XXXX",
        "externalCloudAccountId": "52056612XXXX",
        "cloudPlatform": "aws",
        "PrivateIpAddress": "172.31.1.0",
        "name": ""
    }, {
        "entityId": "/subscriptions/b9a943c8-13c6-4be3-80ed-XXXXXXXX/resourcegroups/rg_cloudbot/providers/microsoft.compute/virtualmachines/cloudbot-target-vm",
        "externalCloudAccountId": "b9a943c8-13c6-4be3-80ed-XXXXXXXX",
        "cloudPlatform": "azure",
        "PublicIpAddress": "51.140.0.0",
        "name": "cloudbot-target-vm"
    }
```

(There are duplicate IP entries where multiple security mechanisms use the 0.0.0.0/0 range - these can be removed fairly easily but they might serve a purpose to someone so I left them in)