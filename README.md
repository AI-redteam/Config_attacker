# Config Attacker

A comprehensive framework for security auditing and penetration testing of AWS Config services. This tool enables security professionals to assess AWS Config configurations, identify misconfigurations, and test detection capabilities in a controlled environment.

![Python Version](https://img.shields.io/badge/python-3.7+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![AWS](https://img.shields.io/badge/AWS-Config-orange.svg)

## ⚠️ Legal Disclaimer

**THIS TOOL IS FOR AUTHORIZED SECURITY TESTING ONLY**

This framework is designed for legitimate security assessments, penetration testing, and auditing purposes. Users must:

- Only use this tool on AWS accounts they own or have explicit written authorization to test
- Comply with all applicable laws and regulations
- Follow AWS Acceptable Use Policy
- Obtain proper authorization before conducting any security assessments

Unauthorized access to AWS resources is illegal. The authors assume no liability for misuse of this tool.

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Menu Options](#menu-options)
- [Use Case Scenarios](#use-case-scenarios)
- [Canned Queries](#canned-queries)
- [Security Considerations](#security-considerations)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

## 🎯 Overview

Config Attacker is a Python-based CLI tool that leverages AWS Config APIs to perform security assessments. It provides penetration testers and security auditors with capabilities to:

- Discover misconfigured resources across AWS environments
- Analyze resource configuration histories
- Test detection and monitoring capabilities
- Assess AWS Config rule effectiveness
- Identify privilege escalation paths through AWS Config

## ✨ Features

### Reconnaissance Capabilities
- **Automated Sensitive Scans**: Pre-built queries to identify common security issues
- **Custom SQL Queries**: Execute custom AWS Config SQL queries
- **Resource History Analysis**: Track configuration changes over time
- **Config Rules Enumeration**: List and analyze deployed Config rules
- **Stored Query Management**: View and manage stored queries

### Evasion & Tampering
- **Recorder Status Monitoring**: Check AWS Config recorder status
- **Recorder Manipulation**: Stop configuration recorders
- **Rule Deletion**: Remove Config rules
- **Query Injection**: Create or modify stored queries
- **Log Channel Hijacking**: Redirect Config logs to attacker-controlled buckets

### Auditing
- **Permissions Audit**: Comprehensive testing of Config API permissions
- **Access Level Assessment**: Determine available privilege levels

## 🚀 Installation

### Prerequisites

- Python 3.7 or higher
- AWS CLI configured with credentials
- Valid AWS credentials with Config permissions

### Step 1: Clone the Repository

```bash
git clone https://github.com/yourusername/config-attacker.git
cd config-attacker
```

### Step 2: Install Dependencies

```bash
pip install -r requirements.txt
```

**Required Python packages:**
```
boto3
questionary
rich
pyfiglet
```

### Step 3: Configure AWS Credentials

Ensure your AWS credentials are configured using one of these methods:

**Option A: AWS CLI Configuration**
```bash
aws configure
```

**Option B: Environment Variables**
```bash
export AWS_ACCESS_KEY_ID="your-access-key"
export AWS_SECRET_ACCESS_KEY="your-secret-key"
export AWS_DEFAULT_REGION="us-east-1"
```

**Option C: IAM Role (for EC2 instances)**
- Attach an IAM role with appropriate Config permissions to your EC2 instance

## ⚙️ Configuration

### Required IAM Permissions

For full functionality, the following IAM permissions are recommended:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "config:SelectResourceConfig",
        "config:GetResourceConfigHistory",
        "config:DescribeConfigRules",
        "config:DescribeConfigurationRecorders",
        "config:ListStoredQueries",
        "config:GetStoredQuery",
        "config:PutStoredQuery",
        "config:StopConfigurationRecorder",
        "config:StartConfigurationRecorder",
        "config:DeleteConfigRule",
        "config:PutDeliveryChannel",
        "config:DescribeDeliveryChannels"
      ],
      "Resource": "*"
    }
  ]
}
```

**Note**: The tool will function with limited permissions. Use the **Permissions Audit** feature to determine available actions.

## 📖 Usage

### Starting the Tool

```bash
python3 config_attacker.py
```

Upon launch, you'll see the main menu with four options:

```
Main Menu
? Select an option:
  > Reconnaissance
    Evasion & Tampering
    Permissions Audit
    Exit
```

### Navigation

- Use **arrow keys** to navigate menus
- Press **Enter** to select an option
- Press **Ctrl+C** to exit at any time

## 🗂️ Menu Options

### 1. Reconnaissance

#### Run Sensitive Scan (Automated)
Executes all pre-built security queries to identify common misconfigurations:

```
- Public S3 buckets
- SSH open to the internet (0.0.0.0/0)
- RDP open to the internet (0.0.0.0/0)
- Unencrypted EBS volumes
- Unencrypted RDS instances
- IAM roles with admin access
- Lambda functions with admin roles
```

**Example Output:**
```
Scanning for: public-s3-buckets
┏━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━┓
┃ resourceId         ┃ resourceName       ┃
┡━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━┩
│ bucket-12345       │ my-public-bucket   │
└────────────────────┴────────────────────┘
```

#### Run Custom SQL Query
Execute custom AWS Config Advanced Query Language queries:

```sql
SELECT 
  resourceId, 
  resourceName, 
  configuration.instanceType 
WHERE 
  resourceType = 'AWS::EC2::Instance' 
  AND configuration.instanceType = 't2.micro'
```

#### Get Resource History
Track configuration changes for a specific resource:

1. Enter resource type (e.g., `AWS::EC2::Instance`)
2. Enter resource ID (e.g., `i-1234567890abcdef0`)
3. View complete configuration history in JSON format

#### Describe Config Rules
Lists all AWS Config rules with their descriptions and ARNs.

#### List Stored Queries
Displays all saved queries in the AWS Config account.

#### Get a Specific Stored Query
Retrieves the full details of a named stored query.

### 2. Evasion & Tampering

⚠️ **Warning**: These actions can disrupt monitoring and compliance in the target AWS account.

#### Check Recorder Status
Displays the status of all AWS Config recorders:

```
┏━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━━┓
┃ Name           ┃ Role ARN      ┃ Recording  ┃ Last Status ┃
┡━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━━┩
│ default        │ arn:aws:iam...│ YES        │ SUCCESS     │
└────────────────┴───────────────┴────────────┴─────────────┘
```

#### Stop a Recorder
Halts AWS Config recording (disables monitoring):

1. Enter recorder name (typically `default`)
2. Confirm action
3. Recording stops, preventing new configuration tracking

#### Delete a Config Rule
Removes a compliance rule:

1. Enter the Config rule name
2. Rule is permanently deleted
3. Associated compliance checks cease

#### Create or Update a Stored Query
Inject or modify saved queries:

1. Choose to use a canned query or write custom SQL
2. Provide a name and optional description
3. Query is saved for future use

#### Hijack Log Delivery Channel
Redirect AWS Config logs to an attacker-controlled S3 bucket:

1. Enter target S3 bucket name
2. Delivery channel is updated
3. All future Config logs are sent to the specified bucket

### 3. Permissions Audit

Performs comprehensive permission testing by attempting various AWS Config API calls:

```
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━┓
┃ API Action                       ┃ Permission Status  ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━┩
│ describe_config_rules            │ ALLOWED            │
│ stop_configuration_recorder      │ DENIED             │
│ delete_config_rule               │ ALLOWED            │
└──────────────────────────────────┴────────────────────┘
```

**Legend:**
- **ALLOWED**: Permission granted
- **DENIED**: Access explicitly denied
- **ALLOWED (Potentially)**: Permission likely available (non-access error)

## 🎯 Use Case Scenarios

### Scenario 1: Initial Reconnaissance

**Objective**: Quickly identify security misconfigurations

```
1. Launch Config Attacker
2. Select "Reconnaissance" → "Run Sensitive Scan (Automated)"
3. Review results for high-risk findings
4. Document exposed resources for reporting
```

**Common Findings:**
- Public S3 buckets that should be private
- Security groups with overly permissive rules
- Unencrypted storage resources
- Over-privileged IAM roles

### Scenario 2: Privilege Escalation Assessment

**Objective**: Identify paths to elevate privileges through AWS Config

```
1. Run "Permissions Audit" to understand available actions
2. If "put_delivery_channel" is allowed:
   - Use "Hijack Log Delivery Channel"
   - Point logs to your controlled bucket
   - Gain access to configuration data
3. If "put_stored_query" is allowed:
   - Create queries to map the environment
   - Identify resources for further exploitation
```

### Scenario 3: Detection Testing

**Objective**: Test security monitoring and incident response

```
1. Coordinate with blue team
2. Execute "Stop a Recorder" action
3. Verify detection mechanisms trigger alerts
4. Execute "Delete a Config Rule" action
5. Confirm monitoring detects rule tampering
6. Review incident response procedures
```

### Scenario 4: Configuration Drift Analysis

**Objective**: Track unauthorized changes to resources

```
1. Select "Get Resource History"
2. Enter target resource type and ID
3. Review configuration timeline
4. Identify when changes occurred
5. Correlate with access logs
```

### Scenario 5: Custom Security Assessments

**Objective**: Hunt for organization-specific misconfigurations

```
1. Select "Run Custom SQL Query"
2. Write targeted queries for your environment:

Example - Find publicly accessible databases:
SELECT resourceId, resourceName, configuration.publiclyAccessible 
WHERE resourceType = 'AWS::RDS::DBInstance' 
AND configuration.publiclyAccessible = true

Example - Identify large EC2 instances:
SELECT resourceId, configuration.instanceType, configuration.state.name
WHERE resourceType = 'AWS::EC2::Instance'
AND configuration.instanceType LIKE '%xlarge%'
```

## 📚 Canned Queries

### Available Pre-built Queries

| Query Name | Description | Risk Level |
|------------|-------------|------------|
| `public-s3-buckets` | S3 buckets with public access | **HIGH** |
| `ssh-open-to-world` | Security groups allowing SSH from 0.0.0.0/0 | **CRITICAL** |
| `rdp-open-to-world` | Security groups allowing RDP from 0.0.0.0/0 | **CRITICAL** |
| `unencrypted-ebs-volumes` | EBS volumes without encryption | **MEDIUM** |
| `unencrypted-rds-instances` | RDS databases without encryption | **HIGH** |
| `iam-roles-with-admin` | IAM roles with Administrator access | **MEDIUM** |
| `lambda-with-admin` | Lambda functions with admin privileges | **HIGH** |

### Query Syntax Reference

AWS Config uses SQL-like syntax for querying resources. Key operators:

- `WHERE` - Filter conditions
- `AND` / `OR` - Logical operators
- `LIKE` - Pattern matching
- `=` / `!=` - Equality operators

**Example Custom Queries:**

```sql
-- Find all resources with specific tags
SELECT resourceId, resourceName, tags 
WHERE tags.Environment = 'Production'

-- Identify stopped EC2 instances
SELECT resourceId, configuration.state.name 
WHERE resourceType = 'AWS::EC2::Instance' 
AND configuration.state.name = 'stopped'

-- Locate Lambda functions in specific VPC
SELECT resourceId, configuration.vpcConfig 
WHERE resourceType = 'AWS::Lambda::Function' 
AND configuration.vpcConfig.vpcId = 'vpc-12345'
```

## 🔒 Security Considerations

### Operational Security

1. **Credential Protection**: Never commit AWS credentials to version control
2. **Logging**: Assume all actions are logged by CloudTrail
3. **Attribution**: Config API calls are attributed to the IAM principal
4. **Reversibility**: Some actions (deletion, stopping recorders) impact monitoring

### Best Practices

- Test in isolated development/staging environments first
- Maintain detailed notes of all actions performed
- Have a rollback plan for evasion techniques
- Coordinate with security operations teams
- Use least-privilege credentials when possible

### Detection Indicators

Actions that may trigger security alerts:

- Stopping Config recorders
- Deleting Config rules
- Modifying delivery channels
- Unusual query patterns
- High volume of `SelectResourceConfig` API calls

## 🔧 Troubleshooting

### Common Issues

#### "Could not find valid AWS credentials"

**Solution:**
```bash
# Verify credentials are configured
aws sts get-caller-identity

# If not configured, run:
aws configure
```

#### "AccessDeniedException" errors

**Cause**: Insufficient IAM permissions

**Solution:**
- Run "Permissions Audit" to identify available actions
- Contact AWS administrator to request additional permissions
- Review the Required IAM Permissions section

#### "ResourceNotFoundException"

**Cause**: Specified resource doesn't exist

**Solution:**
- Verify resource ID and type are correct
- Check you're in the correct AWS region
- Confirm AWS Config is enabled in the account

#### Empty query results

**Possible causes:**
- No resources match the query criteria
- AWS Config is not recording the resource type
- Resources exist in a different region

**Solution:**
```bash
# Check which resource types Config is recording
aws configservice describe-configuration-recorders

# Verify Config is enabled
aws configservice describe-configuration-recorder-status
```

### Debug Mode

To enable verbose output for troubleshooting:

```python
# Add to the top of config_attacker.py
import logging
logging.basicConfig(level=logging.DEBUG)
```

## 🤝 Contributing

Contributions are welcome! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-capability`)
3. Commit changes (`git commit -am 'Add new reconnaissance module'`)
4. Push to branch (`git push origin feature/new-capability`)
5. Open a Pull Request

### Areas for Contribution

- Additional canned queries for common misconfigurations
- Export functionality (CSV, JSON, HTML reports)
- Integration with other AWS services (CloudTrail, GuardDuty)
- Multi-region support
- Automated remediation suggestions

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👥 Authors

- **Your Name** - Initial work

## 🙏 Acknowledgments

- AWS Security teams for comprehensive Config documentation
- The security research community for AWS pentesting methodologies
- Contributors to boto3, rich, and questionary libraries

## 📞 Contact

- Report issues: [GitHub Issues](https://github.com/yourusername/config-attacker/issues)
- Security concerns: security@yourdomain.com

---

**Remember**: With great power comes great responsibility. Use this tool ethically and legally.
