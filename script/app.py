import os
import boto3
import logging
from dotenv import load_dotenv


def error_handler(exception):
    logger.error(exception)
    exit(1)


def debug(msg):
    logger.debug(msg)


def main():
    aws_session = boto3.Session()

    # S3 bucket
    s3_client = aws_session.client('s3')
    if not check_bucket_exists(s3_client):
        print('Need to create bucket!')
        create_bucket(s3_client)
        add_bucket_tag(s3_client)
    # Remove ---------------
    # else:
    #     create_bucket(s3_client)
    # ----------------------

    # DNS ZONE
    route53d_client = aws_session.client('route53domains', 'us-east-1')
    route53_client = aws_session.client('route53', 'us-east-1')
    zone_id = None
    if not check_domain_registration(route53d_client):
        print("Register domain.....!")
        register_domain(route53d_client)
        zone_id = get_dns_zone_id(route53_client)
        add_domain_tag(route53_domains_client=route53d_client,
                       route53_client=route53_client,
                       zone_id=zone_id)

    # DNS RECORD
    if zone_id is None:
        zone_id = get_dns_zone_id(route53_client)
    if not check_dns_rr(route53_client=route53_client, zone_id=zone_id):
        create_dns_a_record(route53_client=route53_client, zone_id=zone_id)

    # SSL
    # acm_client = aws_session.client('acm')
    # acm_client.list_certificates()


def check_domain_registration(route53d_client):
    resp = None
    try:
        resp = route53d_client.list_domains()
    except Exception as Error:
        error_handler(Error)
    if(domain_name in [d['DomainName'] for d in resp['Domains']]):
        return True
    return False


def compose_dns_contact_detail():
    return {
        'CountryCode': dns_admin_country_code,
        'ContactType': 'PERSON',
        'FirstName': dns_admin_first_name,
        'LastName': dns_admin_last_name,
        'PhoneNumber': dns_admin_phone_number,
        'Email': dns_admin_email,
        'City': dns_admin_city,
        'AddressLine1': dns_admin_street_address,
        'State': 'AK',
        'ZipCode': dns_admin_zipcode
    }


def register_domain(route53d_client):
    dns_admin_contact = compose_dns_contact_detail()
    resp = None
    try:
        route53d_client.register_domain(DomainName=domain_name,
                                        AdminContact=dns_admin_contact,
                                        DurationInYears=domain_duration,
                                        RegistrantContact=dns_admin_contact,
                                        TechContact=dns_admin_contact,
                                        PrivacyProtectAdminContact=True,
                                        PrivacyProtectRegistrantContact=True,
                                        PrivacyProtectTechContact=True)
    except Exception as Error:
        error_handler(Error)
    print(resp)
    debug(''.join('AWS Operation ID', resp['OperationId']))


def get_dns_zone_id(route53_client):
    resp = None
    resp = route53_client.list_hosted_zones(MaxItems='10')
    zone = filter(lambda d: d['Name'] == domain_name + '.',
                  resp['HostedZones'])
    zone_id = ((list(zone))[0]['Id']).replace('/hostedzone/', '')
    return zone_id


def add_domain_tag(route53_domains_client, route53_client, zone_id):
    try:
        route53_domains_client.update_tags_for_domain(
            DomainName=domain_name,
            TagsToUpdate=[
                {
                    'Key': aws_tag,
                    'Value': ''
                },
            ]
        )
        route53_client.change_tags_for_resource(
            ResourceType='hostedzone',
            ResourceId=zone_id,
            AddTags=[
                {
                    'Key': aws_tag,
                    'Value': ''
                },
            ]
        )
    except Exception as Error:
        error_handler(Error)


def check_bucket_exists(s3_client):
    resp = None
    try:
        resp = s3_client.list_buckets()
    except Exception as Error:
        error_handler(Error)
    if(bucket_name in [d['Name'] for d in resp['Buckets']]):
        return True
    return False


def create_bucket(s3_client):
    try:
        s3_client.create_bucket(Bucket=bucket_name,
                                CreateBucketConfiguration={
                                    'LocationConstraint': 'eu-north-1'})
        s3_client.put_bucket_website(Bucket=bucket_name,
                                     ChecksumAlgorithm='SHA256',
                                     WebsiteConfiguration={
                                         'IndexDocument': {
                                             'Suffix': 'index.html'
                                         },
                                     }
                                     )
        s3_client.put_public_access_block(Bucket=bucket_name,
                                          ChecksumAlgorithm='SHA256',
                                          PublicAccessBlockConfiguration={
                                              'BlockPublicAcls': False,
                                              'IgnorePublicAcls': False,
                                              'BlockPublicPolicy': False,
                                              'RestrictPublicBuckets': False
                                          },
                                          )
        bucket_policy = '''{{
            "Version": "2012-10-17",
            "Statement": [
                {{
                    "Sid": "PublicReadGetGitObjects",
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::{bucket}/.git*"
                }},
                {{
                    "Sid": "PublicReadGetReadmeObjects",
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::{bucket}/README.md"
                }},
                {{
                    "Sid": "PublicReadGetObject",
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::{bucket}/*"
                }}
            ]
        }}
        '''.format(bucket=bucket_name)
        s3_client.put_bucket_policy(Bucket=bucket_name,
                                    ChecksumAlgorithm='SHA256',
                                    Policy=bucket_policy
                                    )
    except Exception as Error:
        error_handler(Error)


def add_bucket_tag(s3_client):
    try:
        s3_client.put_bucket_tagging(
            Bucket=bucket_name,
            ChecksumAlgorithm='SHA256',
            Tagging={
                'TagSet': [
                    {
                        'Key': aws_tag,
                        'Value': ''
                    },
                ]
            }
        )
    except Exception as Error:
        error_handler(Error)


def check_dns_rr(route53_client, zone_id):
    resp = None
    try:
        resp = route53_client.list_resource_record_sets(
            HostedZoneId=zone_id,
            MaxItems='10')
    except Exception as Error:
        error_handler(Error)

    dns_rr_list = [rr['Name'] for rr in resp['ResourceRecordSets']
                   if rr['Type'] == 'A' and rr['Name'] == domain_name + '.']
    if len(dns_rr_list) > 0:
        return True
    return False


def create_dns_a_record(route53_client, zone_id):
    s3_endpoint = 's3-website.eu-north-1.amazonaws.com.'
    try:
        route53_client.change_resource_record_sets(HostedZoneId=zone_id,
                                                   ChangeBatch={
                                                       'Changes': [
                                                           {
                                                               'Action': 'CREATE',
                                                               'ResourceRecordSet': {
                                                                   'Name': domain_name,
                                                                   'AliasTarget': {
                                                                       'HostedZoneId': 'Z3BAZG2TWCNX0D',
                                                                       'DNSName': s3_endpoint,
                                                                       'EvaluateTargetHealth': False
                                                                   },
                                                                   'Type': 'A',
                                                               },
                                                           },
                                                       ]})
    except Exception as Error:
        error_handler(Error)


if __name__ == "__main__":
    dotenv_path = "../private/.env"
    log_path = "../logs"
    log_level = logging.WARNING
    load_dotenv(dotenv_path=dotenv_path)

    aws_tag = os.getenv('AWS_TAG', default='cv')

    domain_name = os.getenv('DOMAIN_NAME')
    dns_admin_country_code = os.getenv(
        'DOMAIN_ADMIN_COUNTRY_CODE', default='US')
    dns_admin_first_name = os.getenv('DNS_ADMIN_FIRST_NAME')
    dns_admin_last_name = os.getenv('DNS_ADMIN_LAST_NAME')
    dns_admin_phone_number = os.getenv('DNS_ADMIN_PHONENUMBER')
    dns_admin_email = os.getenv('DNS_ADMIN_EMAIL')
    dns_admin_city = os.getenv('DNS_ADMIN_CITY')
    dns_admin_street_address = os.getenv('DNS_ADMIN_ADDRESSLINE1')
    dns_admin_state = os.getenv('DNS_ADMIN_STATE')
    dns_admin_zipcode = os.getenv('DNS_ADMIN_ZIPCODE')
    domain_duration = int(os.getenv('DOMAIN_DURATION', default=1))

    bucket_name = domain_name

    logging.basicConfig(filename=log_path + '/app.log', level=log_level,
                        format='%(asctime)s %(levelname)s %(name)s %(message)s')
    logger = logging.getLogger(__name__)

    main()
