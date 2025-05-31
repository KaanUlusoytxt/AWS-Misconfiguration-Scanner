import boto3
import json
from datetime import datetime

report = {
    "public_s3_buckets": [],
    "open_security_groups": [],
    "risky_iam_policies": [],
    "public_rds_instances": [],
    "risk_score": 0
}

def check_public_s3_buckets():
    s3 = boto3.client('s3')
    buckets = s3.list_buckets()

    for bucket in buckets['Buckets']:
        bucket_name = bucket['Name']
        acl = s3.get_bucket_acl(Bucket=bucket_name)
        for grant in acl['Grants']:
            if grant['Grantee'].get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                report["public_s3_buckets"].append(bucket_name)
                report["risk_score"] += 25  # s3 için risk puanı

def check_open_security_groups():
    ec2 = boto3.client('ec2')
    security_groups = ec2.describe_security_groups()['SecurityGroups']

    for sg in security_groups:
        open_ports = []
        for permission in sg['IpPermissions']:
            if permission.get('IpRanges'):
                for ip_range in permission['IpRanges']:
                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                        port = permission.get('FromPort', 'All')
                        open_ports.append(port)
                        if port in [22, 3389]:
                            report["risk_score"] += 30  # kritik portlar
                        else:
                            report["risk_score"] += 10  # diğer açık portlar
        if open_ports:
            report["open_security_groups"].append({
                "group_id": sg['GroupId'],
                "group_name": sg.get('GroupName', ''),
                "open_ports": open_ports
            })

def check_risky_iam_policies():
    iam = boto3.client('iam')
    policies = iam.list_policies(Scope='Local')['Policies']

    for policy in policies:
        policy_name = policy['PolicyName']
        policy_arn = policy['Arn']
        policy_version = iam.get_policy_version(
            PolicyArn=policy_arn,
            VersionId=policy['DefaultVersionId']
        )
        doc = policy_version['PolicyVersion']['Document']
        doc_json = json.dumps(doc)
        if '"*"' in doc_json:
            report["risky_iam_policies"].append(policy_name)
            report["risk_score"] += 30  # iam policy için risk puanı

def check_public_rds_instances():
    rds = boto3.client('rds')
    instances = rds.describe_db_instances()['DBInstances']

    for instance in instances:
        if instance.get('PubliclyAccessible'):
            report["public_rds_instances"].append(instance['DBInstanceIdentifier'])
            report["risk_score"] += 20  # public rds için risk puanı

def generate_html_report():
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    html = f"<h1>AWS Misconfiguration Report</h1><p>Generated on {now}</p>"

    # Risk skoru bölümü renkli
    if report['risk_score'] <= 30:
        color = "green"
    elif report['risk_score'] <= 70:
        color = "orange"
    else:
        color = "red"

    html += f"<h2 style='color:{color};'>Total Risk Score: {report['risk_score']}/100</h2>"

    html += "<h2>Public S3 Buckets</h2><ul>"
    for bucket in report["public_s3_buckets"]:
        html += f"<li>{bucket}</li>"
    html += "</ul>"

    html += "<h2>Open Security Groups</h2><ul>"
    for sg in report["open_security_groups"]:
        html += f"<li>{sg['group_id']} ({sg['group_name']}): Ports {sg['open_ports']}</li>"
    html += "</ul>"

    html += "<h2>Risky IAM Policies</h2><ul>"
    for policy in report["risky_iam_policies"]:
        html += f"<li>{policy}</li>"
    html += "</ul>"

    html += "<h2>Public RDS Instances</h2><ul>"
    for rds in report["public_rds_instances"]:
        html += f"<li>{rds}</li>"
    html += "</ul>"

    with open("report.html", "w") as f:
        f.write(html)
    print("✅ HTML report saved as report.html")

if __name__ == "__main__":
    print("🔍 Scanning public S3 buckets...")
    check_public_s3_buckets()

    print("🔍 Scanning open security groups...")
    check_open_security_groups()

    print("🔍 Scanning risky IAM policies...")
    check_risky_iam_policies()

    print("🔍 Scanning public RDS instances...")
    check_public_rds_instances()

    print(f"⚠️ Total Risk Score: {report['risk_score']}/100")

    print("📝 Generating HTML report...")
    generate_html_report()
