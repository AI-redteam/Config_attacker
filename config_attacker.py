#!/usr/bin/env python3
import boto3
import json
import os
import sys
from botocore.exceptions import ClientError

# UI/Formatting Libraries
import questionary
from rich.console import Console
from rich.table import Table
from rich.json import JSON
import pyfiglet

# --- Canned Query Definitions ---
CANNED_QUERIES = {
    "public-s3-buckets": "SELECT resourceId, resourceName, configuration.publicAccessBlockConfiguration WHERE resourceType = 'AWS::S3::Bucket' AND configuration.publicAccessBlockConfiguration.blockPublicAcls = false",
    "ssh-open-to-world": "SELECT resourceId, resourceName, configuration.ipPermissions WHERE resourceType = 'AWS::EC2::SecurityGroup' AND configuration.ipPermissions.ipRanges LIKE '%0.0.0.0/0%' AND configuration.ipPermissions.fromPort = 22",
    "rdp-open-to-world": "SELECT resourceId, resourceName, configuration.ipPermissions WHERE resourceType = 'AWS::EC2::SecurityGroup' AND configuration.ipPermissions.ipRanges LIKE '%0.0.0.0/0%' AND configuration.ipPermissions.fromPort = 3389",
    "unencrypted-ebs-volumes": "SELECT resourceId, resourceName, configuration.encrypted WHERE resourceType = 'AWS::EC2::Volume' AND configuration.encrypted = false",
    "unencrypted-rds-instances": "SELECT resourceId, resourceName, configuration.storageEncrypted WHERE resourceType = 'AWS::RDS::DBInstance' AND configuration.storageEncrypted = false",
    "iam-roles-with-admin": "SELECT resourceId, resourceName WHERE resourceType = 'AWS::IAM::Role' AND relationships.resourceName = 'AdministratorAccess'",
    "lambda-with-admin": "SELECT resourceId, resourceName, relationships.resourceId WHERE resourceType = 'AWS::Lambda::Function' AND relationships.relationshipName = 'Is associated with Role' AND relationships.resourceName = 'AdministratorAccess'",
}


class ConfigPenTestFramework:
    """
    Handles all the backend logic for interacting with the AWS Config API.
    This class returns data, it does not print to the console.
    """
    def __init__(self):
        try:
            self.config_client = boto3.client('config')
            # A simple check to ensure credentials are valid
            self.config_client.describe_configuration_recorders()
        except ClientError as e:
            if e.response['Error']['Code'] == 'UnrecognizedClientException' or 'Credentials' in str(e):
                 print(f"\nFATAL ERROR: Could not find valid AWS credentials. Please configure them (e.g., run 'aws configure').")
                 sys.exit(1)
            # Other errors might be permissions related, which is fine to handle later.
        except Exception as e:
            print(f"An unexpected error occurred during initialization: {e}")
            sys.exit(1)

    def select_resources(self, query):
        paginator = self.config_client.get_paginator('select_resource_config')
        pages = paginator.paginate(Expression=query)
        all_results = []
        for page in pages:
            all_results.extend([json.loads(r) for r in page['Results']])
        return all_results

    def get_history(self, resource_type, resource_id):
        paginator = self.config_client.get_paginator('get_resource_config_history')
        pages = paginator.paginate(resourceType=resource_type, resourceId=resource_id)
        history = []
        for page in pages:
            history.extend(page['configurationItems'])
        return history

    def describe_rules(self):
        return self.config_client.describe_config_rules().get('ConfigRules', [])

    def check_recorders(self):
        return self.config_client.describe_configuration_recorders().get('ConfigurationRecorders', [])

    def stop_recorder(self, recorder_name):
        self.config_client.stop_configuration_recorder(ConfigurationRecorderName=recorder_name)

    def delete_rule(self, rule_name):
        self.config_client.delete_config_rule(ConfigRuleName=rule_name)

    def list_stored_queries(self):
        paginator = self.config_client.get_paginator('list_stored_queries')
        pages = paginator.paginate()
        queries = []
        for page in pages:
            queries.extend(page['StoredQueryMetadata'])
        return queries

    def get_stored_query(self, name):
        response = self.config_client.get_stored_query(QueryName=name)
        return response.get('StoredQuery')

    def put_stored_query(self, name, expression, description=""):
        query_to_put = {'QueryName': name, 'Expression': expression}
        if description:
            query_to_put['Description'] = description
        return self.config_client.put_stored_query(StoredQuery=query_to_put)
        
    def put_delivery_channel(self, bucket_name):
        channels = self.config_client.describe_delivery_channels()
        if not channels['DeliveryChannels']:
            raise ValueError("No delivery channel found to modify.")
            
        current_channel = channels['DeliveryChannels'][0]
        new_channel = {'name': current_channel['name'], 's3BucketName': bucket_name}
        if 's3KeyPrefix' in current_channel:
            new_channel['s3KeyPrefix'] = current_channel['s3KeyPrefix']
        
        self.config_client.put_delivery_channel(DeliveryChannel=new_channel)
        return new_channel

    def audit_permissions(self):
        permissions = {}
        tests = [
            ("describe_config_rules", self.config_client.describe_config_rules, {}),
            ("describe_configuration_recorders", self.config_client.describe_configuration_recorders, {}),
            ("get_resource_config_history", self.config_client.get_resource_config_history, {'resourceType': 'AWS::EC2::VPC', 'resourceId': 'vpc-00000000'}),
            ("stop_configuration_recorder", self.config_client.stop_configuration_recorder, {'ConfigurationRecorderName': 'fake-recorder'}),
            ("start_configuration_recorder", self.config_client.start_configuration_recorder, {'ConfigurationRecorderName': 'fake-recorder'}),
            ("delete_config_rule", self.config_client.delete_config_rule, {'ConfigRuleName': 'fake-rule'}),
            ("put_delivery_channel", self.config_client.put_delivery_channel, {'DeliveryChannel': {'name': 'fake-channel', 's3BucketName': 'fake-bucket'}})
        ]
        for name, func, kwargs in tests:
            try:
                func(**kwargs)
                permissions[name] = "[bold green]ALLOWED[/bold green]"
            except ClientError as e:
                if e.response['Error']['Code'] == 'AccessDeniedException':
                    permissions[name] = "[bold red]DENIED[/bold red]"
                else:
                    permissions[name] = f"[yellow]ALLOWED (Potentially - Error: {e.response['Error']['Code']})[/yellow]"
        return permissions


class ConfigAttackerCLI:
    """
    Handles the user interface, menus, and output formatting.
    """
    def __init__(self):
        self.framework = ConfigPenTestFramework()
        self.console = Console()

    def print_banner(self):
        os.system('cls' if os.name == 'nt' else 'clear')
        banner = pyfiglet.figlet_format("Config Attacker", font="slant")
        self.console.print(f"[bold cyan]{banner}[/bold cyan]")
        self.console.print("       [A framework for auditing and testing AWS Config]", style="italic cyan")
        self.console.print("-" * 60)

    def handle_error(self, ex):
        if isinstance(ex, ClientError):
            error_code = ex.response.get("Error", {}).get("Code")
            self.console.print(f"\n[bold red]AWS API ERROR[/bold red]: [white]{error_code}[/white]")
            self.console.print(f"  [red]Message: {ex.response.get('Error', {}).get('Message')}[/red]")
        elif isinstance(ex, ValueError):
             self.console.print(f"\n[bold red]ERROR[/bold red]: [white]{ex}[/white]")
        else:
            self.console.print(f"\n[bold red]An unexpected error occurred[/bold red]: {ex}")

    def show_recon_menu(self):
        while True:
            self.print_banner()
            choice = questionary.select(
                "Reconnaissance Menu",
                choices=[
                    "Run Sensitive Scan (Automated)",
                    "Run Custom SQL Query",
                    "Get Resource History",
                    "Describe Config Rules",
                    "List Stored Queries",
                    "Get a Specific Stored Query",
                    "Go Back"
                ]).ask()

            if choice == "Go Back" or choice is None: break
            
            try:
                if choice == "Run Sensitive Scan (Automated)":
                    for desc, query in CANNED_QUERIES.items():
                        self.console.print(f"\n[bold yellow]Scanning for: {desc}[/bold yellow]")
                        results = self.framework.select_resources(query)
                        if not results: self.console.print("[green]  -> No results found.[/green]"); continue
                        table = Table(show_header=True, header_style="bold magenta")
                        headers = sorted(list(results[0].keys()))
                        for header in headers: table.add_column(header)
                        for item in results: table.add_row(*[str(item.get(h, 'N/A')) for h in headers])
                        self.console.print(table)
                
                elif choice == "Get Resource History":
                    rtype = questionary.text("Enter the resource type (e.g., AWS::EC2::Instance):").ask()
                    rid = questionary.text("Enter the resource ID (e.g., i-1234567890abcdef0):").ask()
                    if rtype and rid:
                        history = self.framework.get_history(rtype, rid)
                        self.console.print(JSON(json.dumps(history, default=str)))

                elif choice == "Describe Config Rules":
                    rules = self.framework.describe_rules()
                    table = Table("Rule Name", "ARN", "Description", header_style="bold magenta")
                    for rule in rules:
                        table.add_row(rule['ConfigRuleName'], rule['ConfigRuleArn'], rule.get('Description', 'N/A'))
                    self.console.print(table)

                elif choice == "List Stored Queries":
                    queries = self.framework.list_stored_queries()
                    table = Table("Name", "ARN", "Description", header_style="bold magenta")
                    for q in queries:
                        table.add_row(q['QueryName'], q['QueryArn'], q.get('Description', 'N/A'))
                    self.console.print(table)
                
                elif choice == "Get a Specific Stored Query":
                    name = questionary.text("Enter the name of the query:").ask()
                    if name:
                        query = self.framework.get_stored_query(name)
                        self.console.print(JSON(json.dumps(query)))

                elif choice == "Run Custom SQL Query":
                    expression = questionary.text("Enter the full SQL expression:").ask()
                    if expression:
                        results = self.framework.select_resources(expression)
                        self.console.print(JSON(json.dumps(results)))
            except Exception as e:
                self.handle_error(e)
            questionary.press_any_key_to_continue().ask()

    def show_evasion_menu(self):
        while True:
            self.print_banner()
            choice = questionary.select(
                "Evasion & Tampering Menu",
                choices=[
                    "Check Recorder Status",
                    "Stop a Recorder",
                    "Delete a Config Rule",
                    "Create or Update a Stored Query",
                    "Hijack Log Delivery Channel",
                    "Go Back"
                ]).ask()
            
            if choice == "Go Back" or choice is None: break
            try:
                if choice == "Check Recorder Status":
                    recorders = self.framework.check_recorders()
                    table = Table("Name", "Role ARN", "Recording", "Last Status", header_style="bold magenta")
                    for r in recorders:
                        status = r.get('lastStatus', 'N/A')
                        is_recording = "[bold green]YES[/]" if r.get('recordingGroup', {}).get('allSupported', False) else "[bold red]NO[/]"
                        table.add_row(r['name'], r['roleARN'], is_recording, status)
                    self.console.print(table)

                elif choice == "Stop a Recorder":
                    name = questionary.text("Enter the name of the recorder to stop:").ask()
                    if name:
                        self.framework.stop_recorder(name)
                        self.console.print(f"\n[bold green]Success![/bold green] Sent command to stop recorder '{name}'.")

                elif choice == "Delete a Config Rule":
                    name = questionary.text("Enter the name of the config rule to delete:").ask()
                    if name:
                        self.framework.delete_rule(name)
                        self.console.print(f"\n[bold green]Success![/bold green] Deleted config rule '{name}'.")

                elif choice == "Create or Update a Stored Query":
                    name = questionary.text("Enter the name for the query:").ask()
                    if not name: continue
                    use_canned = questionary.confirm("Use a canned expression?").ask()
                    if use_canned:
                        canned_choice = questionary.select("Select a canned query:", choices=list(CANNED_QUERIES.keys())).ask()
                        expression = CANNED_QUERIES[canned_choice]
                    else:
                        expression = questionary.text("Enter the custom SQL expression:").ask()
                    if expression:
                        desc = questionary.text("Enter an optional description:").ask()
                        self.framework.put_stored_query(name, expression, desc)
                        self.console.print(f"\n[bold green]Success![/bold green] Stored query '{name}' has been created/updated.")

                elif choice == "Hijack Log Delivery Channel":
                    bucket = questionary.text("Enter the name of the S3 bucket to hijack to:").ask()
                    if bucket:
                        self.framework.put_delivery_channel(bucket)
                        self.console.print(f"\n[bold green]Success![/bold green] Delivery channel has been pointed to '{bucket}'.")
            except Exception as e:
                self.handle_error(e)
            questionary.press_any_key_to_continue().ask()

    def run_permissions_audit(self):
        self.print_banner()
        self.console.print("[yellow]Running a full permissions audit...[/yellow]")
        with self.console.status("Attempting various API calls..."):
            permissions = self.framework.audit_permissions()
        
        table = Table("API Action", "Permission Status", header_style="bold magenta")
        for action, status in permissions.items():
            table.add_row(action, status)
        self.console.print(table)
        questionary.press_any_key_to_continue().ask()

    def run(self):
        while True:
            self.print_banner()
            try:
                action = questionary.select(
                    "Main Menu",
                    choices=[
                        "Reconnaissance",
                        "Evasion & Tampering",
                        "Permissions Audit",
                        "Exit"
                    ]
                ).ask()

                if action == "Reconnaissance": self.show_recon_menu()
                elif action == "Evasion & Tampering": self.show_evasion_menu()
                elif action == "Permissions Audit": self.run_permissions_audit()
                elif action == "Exit" or action is None:
                    self.console.print("[bold cyan]Exiting. Stay safe![/bold cyan]")
                    sys.exit(0)
            except KeyboardInterrupt:
                self.console.print("\n[bold cyan]Exiting. Stay safe![/bold cyan]")
                sys.exit(0)

if __name__ == "__main__":
    cli = ConfigAttackerCLI()
    cli.run()
