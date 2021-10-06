import logging
import os
import re
import time

import boto3
import requests
from requests_aws4auth import AWS4Auth

# Get environment variables
REGION = os.environ.get('AWS_REGION')
OPEN_SEARCH_INDEX = os.environ.get('OPEN_SEARCH_INDEX')
OPEN_SEARCH_ENDPOINT = os.environ.get('OPEN_SEARCH_ENDPOINT')
ELASTIC_SEARCH_SERVICE = os.environ.get('ELASTIC_SEARCH_SERVICE')

# Open search doc URL
OPEN_SEARCH_DOC_URL = OPEN_SEARCH_ENDPOINT + OPEN_SEARCH_INDEX + "/_doc"

# REGEX PATTERN for ELB log
ELB_LOG_PATTERN = r'([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*):([0-9]*) ([^ ]*)[:-]([0-9]*) ([-.0-9]*) ([-.0-9]*) ([-.0-9]*) (|[' \
                  r'-0-9]*) (-|[-0-9]*) ([-0-9]*) ([-0-9]*) \"([^ ]*) (.*) (- |[^ ]*)\" \"([^\"]*)\" ([A-Z0-9-]+) ([' \
                  r'A-Za-z0-9.-]*) ([^ ]*) \"([^\"]*)\" \"([^\"]*)\" \"([^\"]*)\" ([-.0-9]*) ([^ ]*) \"([^\"]*)\" \"(' \
                  r'[^\"]*)\" \"([^ ]*)\" \"([^\s]+?)\" \"([^\s]+)\" \"([^ ]*)\" \"([^ ]*)\" '

ELB_LOG_FIELDS = [
    "type",
    "timestamp",
    "elb",
    "client_ip",
    "client_port",
    "target_ip",
    "target_port",
    "request_processing_time",
    "backend_processing_time",
    "response_processing_time",
    "elb_status_code",
    "target_status_code",
    "received_bytes",
    "sent_bytes",
    "request_verb",
    "request_url",
    "request_proto",
    "user_agent",
    "ssl_cipher",
    "ssl_protocol",
    "target_group_arn",
    "trace_id",
    "domain_name",
    "chosen_cert_arn",
    "matched_rule_priority",
    "request_creation_time",
    "actions_executed",
    "redirect_url",
    "lambda_error_reason",
    "target_port_list",
    "target_status_code_list",
    "classification",
    "classification_reason"
]

credentials = boto3.Session().get_credentials()
headers = {"Content-Type": "application/json"}

awsauth = AWS4Auth(credentials.access_key, credentials.secret_key, REGION, ELASTIC_SEARCH_SERVICE,
                   session_token=credentials.token)

s3 = boto3.client('s3')

"""
Parses ELB log file to appropriate key: value
"""


def parse(line):
    matches = re.search(ELB_LOG_PATTERN, line)

    payload = {}
    for i, column in enumerate(ELB_LOG_FIELDS):
        payload[column] = matches.group(i + 1)

    return payload


def save_log(event, context):
    for record in event["Records"]:
        # From the event record, get the bucket name and key.
        bucket_name = record['s3']['bucket']['name']
        file_key = record['s3']['object']['key']

        # From the S3 object, read the file and split the lines
        obj = s3.get_object(Bucket=bucket_name, Key=file_key)

        body = obj['Body'].read()
        lines = body.splitlines()

        for line in lines:
            payload = parse(line.decode('utf-8'))

            r = requests.post(OPEN_SEARCH_DOC_URL, auth=awsauth, json=payload, headers=headers)

            log_body = {
                "bucket": bucket_name,
                "file_key": file_key,
                "open_search_post_response": r.content
            }

            logging.info(log_body)
