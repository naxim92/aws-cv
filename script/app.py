import os
import boto3
import logging
import mimetypes
from dotenv import load_dotenv
from time import sleep
# from time import time


def error_handler(exception):
    logger.error(exception)
    exit(1)


def log_handler(msg):
    print(msg)


def debug(msg):
    logger.debug(msg)


def main():
    aws_session = boto3.Session()

    # S3 bucket
    s3_client = aws_session.client('s3')
    if not check_bucket_exists(s3_client):
        log_handler('Creating bucket....')
        create_bucket(s3_client)
        add_bucket_tag(s3_client)

    # DNS ZONE
    route53d_client = aws_session.client('route53domains', 'us-east-1')
    route53_client = aws_session.client('route53', 'us-east-1')
    zone_id = None
    if not check_domain_registration(route53d_client):
        log_handler("Registering domain....")
        register_domain(route53d_client)
        zone_id = get_dns_zone_id(route53_client)
        add_domain_tag(route53_domains_client=route53d_client,
                       route53_client=route53_client,
                       zone_id=zone_id)

    if zone_id is None:
        zone_id = get_dns_zone_id(route53_client)
    # I decided to chooze Cloudfront distribution against S3 bucket static website hosting
    # So it doesn't need to configure DNS for cloudfront working
    # if not check_dns_rr(route53_client=route53_client, zone_id=zone_id, type='A'):
    #     log_handler('Creating DNS RR....')
    #     create_dns_a_record(route53_client=route53_client, zone_id=zone_id)

    # SSL
    acm_client = aws_session.client('acm', 'us-east-1')
    ssl_exists, ssl_status, ssl_arn = check_ssl_cert(acm_client)
    if not ssl_exists:
        log_handler('Creating SSL request....')
        create_ssl_request(acm_client)
        sleep(5)

        for i in range(5):
            sleep(2)
            ssl_exists, ssl_status, ssl_arn = check_ssl_cert(acm_client)
            if ssl_exists:
                break
        if not ssl_exists:
            error_handler('Something is going wrong while validating ssl cert')
    if ssl_exists and ssl_status == 'PENDING_VALIDATION':
        log_handler('Validating SSL request....')
        validate_ssl(acm_client=acm_client,
                     route53_client=route53_client,
                     zone_id=zone_id,
                     cert_arn=ssl_arn)

    # Cloudfront
    cf_client = aws_session.client('cloudfront')
    cf_distribution_exists, cf_distribution_domain = check_cf_distribution(
        cf_client)
    if not cf_distribution_exists:
        create_cf_distribution(cf_client, ssl_arn)
        cf_distribution_exists, cf_distribution_domain = check_cf_distribution(
            cf_client)

    # DNS RECORD
    if not check_dns_rr(route53_client=route53_client, zone_id=zone_id, rr_type='A'):
        log_handler('Creating DNS RR....')
        create_dns_a_record(route53_client=route53_client,
                            zone_id=zone_id,
                            s3=False,
                            cf_domain_name=cf_distribution_domain)

    # CV site
    log_handler('Uploading CV to AWS....')
    uploadSiteCode(s3_client)


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
    error_handler(''.join('AWS Operation ID', resp['OperationId']))


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


def check_dns_rr(route53_client, zone_id, rr_type='A'):
    resp = None
    try:
        resp = route53_client.list_resource_record_sets(
            HostedZoneId=zone_id,
            MaxItems='10')
    except Exception as Error:
        error_handler(Error)

    dns_rr_list = [rr['Name'] for rr in resp['ResourceRecordSets']
                   if rr['Type'] == rr_type and rr['Name'] == domain_name + '.']
    if len(dns_rr_list) > 0:
        return True
    return False


def create_dns_a_record(route53_client, zone_id, s3=True, cf_domain_name=''):
    s3_endpoint = 's3-website.eu-north-1.amazonaws.com.'
    if s3:
        endpoint = s3_endpoint
        hostedZoneId = 'Z3BAZG2TWCNX0D'
    else:
        endpoint = cf_domain_name
        hostedZoneId = 'Z2FDTNDATAQYW2'
    try:
        route53_client.change_resource_record_sets(HostedZoneId=zone_id,
                                                   ChangeBatch={
                                                       'Changes': [
                                                           {
                                                               'Action': 'CREATE',
                                                               'ResourceRecordSet': {
                                                                   'Name': domain_name,
                                                                   'AliasTarget': {
                                                                       # Z3BAZG2TWCNX0D - s3
                                                                       # Z2FDTNDATAQYW2 - cloudfront
                                                                       'HostedZoneId': hostedZoneId,
                                                                       'DNSName': endpoint,
                                                                       'EvaluateTargetHealth': False
                                                                   },
                                                                   'Type': 'A',
                                                               },
                                                           },
                                                       ]})
    except Exception as Error:
        error_handler(Error)


def create_dns_cname_record(route53_client, zone_id, rr_name, rr_value):
    try:
        route53_client.change_resource_record_sets(HostedZoneId=zone_id,
                                                   ChangeBatch={
                                                       'Changes': [
                                                           {
                                                               'Action': 'CREATE',
                                                               'ResourceRecordSet': {
                                                                   'Name': rr_name,
                                                                   'Type': 'CNAME',
                                                                   'TTL': 300,
                                                                   'ResourceRecords': [{'Value': rr_value}]
                                                               },
                                                           },
                                                       ]})
    except Exception as Error:
        error_handler(Error)


def uploadSiteCode(s3_client):
    try:
        for root, dirs, files in os.walk(cv_site_path):
            for file in files:
                bucket_file_path = file
                folder = (str(root).replace('../cv/', '').replace('\\', '/'))
                if folder != '':
                    bucket_file_path = ''.join([folder, '/', file])
                content_type = mimetypes.guess_type(file)
                if content_type[0] is None:
                    content_type = 'text/plain'
                else:
                    content_type = content_type[0]
                s3_client.upload_file(os.path.join(root, file),
                                      bucket_name,
                                      bucket_file_path,
                                      ExtraArgs={'ContentType': content_type})
    except Exception as Error:
        error_handler(Error)


def check_ssl_cert(acm_client):
    resp = None
    try:
        resp = acm_client.list_certificates()
    except Exception as Error:
        error_handler(Error)

    ssl_list = [ssl for ssl in resp['CertificateSummaryList']
                if ssl['DomainName'] == domain_name]
    if len(ssl_list) == 0:
        return False, None, None
    return True, ssl_list[0]['Status'], ssl_list[0]['CertificateArn']


def create_ssl_request(acm_client):
    resp = None
    try:
        resp = acm_client.request_certificate(DomainName=domain_name,
                                              ValidationMethod='DNS',
                                              Tags=[
                                                  {
                                                      'Key': aws_tag,
                                                      'Value': ''
                                                  }
                                              ]
                                              )
    except Exception as Error:
        error_handler(Error)
    return resp['CertificateArn']


def check_cf_distribution(cf_client):
    resp = None
    try:
        resp = cf_client.list_distributions()
    except Exception as Error:
        error_handler(Error)

    if resp['DistributionList']['Quantity'] == 0:
        return False, None
    list_distributions = [d for d in resp['DistributionList']['Items']
                          if 'Origins' in d
                          and 'Items' in d['Origins']
                          and len(d['Origins']['Items']) > 0
                          and d['Origins']['Items'][0]['Id'] == domain_name]
    if len(list_distributions) == 0:
        return False, None
    return True, list_distributions[0]['DomainName']


def create_cf_distribution(cf_client, cert_arn):
    resp = None
    origin_domain = '{0}.s3-website.{1}.amazonaws.com'.format(
        domain_name, aws_region)
    try:
        resp = cf_client.create_distribution_with_tags(
            DistributionConfigWithTags=dict({
                'DistributionConfig': {
                    # 'CallerReference': str(time()).replace(".", ""),
                    'CallerReference': domain_name,
                    'DefaultRootObject': 'index.html',
                    'Aliases':
                    {
                        'Quantity': 1,
                        'Items': [
                            domain_name,
                        ]
                    },
                    'Origins': {
                        'Quantity': 1,
                        'Items': [
                            {
                                'Id': domain_name,
                                'DomainName': origin_domain,
                                # 'OriginPath': '/index.html',
                                'CustomOriginConfig': {
                                    'HTTPPort': 80,
                                    'HTTPSPort': 443,
                                    'OriginProtocolPolicy': 'http-only',
                                },
                                'OriginShield': {
                                    'Enabled': False
                                }
                            }
                        ]
                    },
                    'DefaultCacheBehavior': {
                        'TargetOriginId': domain_name,
                        'ViewerProtocolPolicy': 'redirect-to-https',
                        'AllowedMethods': {
                            'Quantity': 2,
                            'Items': ['GET', 'HEAD'],
                        },
                        'Compress': True,
                        'MinTTL': 0,
                        'ForwardedValues': {
                            'Cookies': {'Forward': 'all'},
                            'Headers': {'Quantity': 0},
                            'QueryString': False,
                            'QueryStringCacheKeys': {"Quantity": 0}
                        },
                    },
                    'PriceClass': 'PriceClass_100',
                    'Enabled': True,
                    'ViewerCertificate': {
                        'CloudFrontDefaultCertificate': False,
                        'ACMCertificateArn': cert_arn,
                        'MinimumProtocolVersion': 'TLSv1.2_2018',
                        'SSLSupportMethod': 'sni-only'
                    },
                    'Comment': ''
                },
                'Tags': {
                    'Items': [
                        {
                            'Key': aws_tag,
                            'Value': ''
                        }
                    ]
                }
            }
            ))
    except Exception as Error:
        error_handler(Error)
    if 'Distribution' in resp and 'DomainName' in resp['Distribution']:
        cf_domain_name = resp['Distribution']['DomainName']
        log_handler(
            'Cloudfront distribution is getting ready in several minutes on https://{0}'.format(cf_domain_name))
    else:
        error_handler(
            'Something is going wrong while creating Cloudfront distribution')


def validate_ssl(acm_client, route53_client, zone_id, cert_arn):
    resp = None
    try:
        resp = acm_client.describe_certificate(CertificateArn=cert_arn)
    except Exception as Error:
        error_handler(Error)
    # ISSUED
    # rr_type = resp['ResourceRecord']['Type']
    rr_values = resp['Certificate']['DomainValidationOptions'][0]
    if 'ResourceRecord' in rr_values:
        rr_name = rr_values['ResourceRecord']['Name']
        rr_value = rr_values['ResourceRecord']['Value']
        create_dns_cname_record(route53_client, zone_id, rr_name, rr_value)
    else:
        error_handler('Something is going wrong while validating ssl cert')

    issued = False
    for t in [10, 20, 30, 60, 120, 120, 60, 30, 30]:
        log_handler(
            'Wait for {0} sec and check SSL cert validation....'.format(str(t)))
        resp = None
        sleep(t)
        try:
            resp = acm_client.describe_certificate(CertificateArn=cert_arn)
        except Exception as Error:
            error_handler(Error)
        if resp['Certificate']['DomainValidationOptions'][0]['ValidationStatus'] == 'SUCCESS':
            issued = True
            log_handler('SSL certificate is issued successfully')
            break
    if not issued:
        error_handler('Something is going wrong while validating ssl cert')


if __name__ == "__main__":
    dotenv_path = "../private/.env"
    log_path = "../logs"
    log_level = logging.WARNING
    load_dotenv(dotenv_path=dotenv_path)

    cv_site_path = '../cv/'
    aws_tag = os.getenv('AWS_TAG', default='cv')
    aws_region = os.getenv('AWS_REGION')

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
