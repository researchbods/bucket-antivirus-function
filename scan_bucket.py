#! /usr/bin/env python
# -*- coding: utf-8 -*-

# Upside Travel, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import argparse
import json
import sys

import boto3

from common import AV_STATUS_METADATA
from common import AV_TIMESTAMP_METADATA
from datetime import datetime, timedelta


# Get all objects in an S3 bucket that have not been previously scanned
def get_objects(s3_client, s3_bucket_name, limit, start_date, end_date):

    s3_object_list = []
    count = 0

    s3_list_objects_result = {"IsTruncated": True}
    while s3_list_objects_result["IsTruncated"]:
        print(f"Objects checked: {count}")
        print(f"Update: Objects to be scanned = {len(s3_object_list)}")
        s3_list_objects_config = {"Bucket": s3_bucket_name}
        continuation_token = s3_list_objects_result.get("NextContinuationToken")
        if continuation_token:
            s3_list_objects_config["ContinuationToken"] = continuation_token
        s3_list_objects_result = s3_client.list_objects_v2(**s3_list_objects_config)
        if "Contents" not in s3_list_objects_result:
            break
        if limit:
            if len(s3_object_list) >= limit:
                break
        
        for key in s3_list_objects_result["Contents"]:
            count += 1
            key_name = key["Key"]
            upload_date = key["LastModified"].replace(tzinfo=None)

            if upload_date >= start_date and upload_date <= end_date:
                # Don't include objects that have been scanned
                if not object_previously_scanned(s3_client, s3_bucket_name, key_name):
                    s3_object_list.append(key_name)

    return s3_object_list


# Determine if an object has been previously scanned for viruses
def object_previously_scanned(s3_client, s3_bucket_name, key_name):
    s3_object_tags = s3_client.get_object_tagging(Bucket=s3_bucket_name, Key=key_name)
    if "TagSet" not in s3_object_tags:
        return False
    for tag in s3_object_tags["TagSet"]:
        if tag["Key"] in [AV_STATUS_METADATA, AV_TIMESTAMP_METADATA]:
            return True
    return False


# Scan an S3 object for viruses by invoking the lambda function
# Skip any objects that have already been scanned
def scan_object(lambda_client, lambda_function_name, s3_bucket_name, key_name):

    print("Scanning: {}/{}".format(s3_bucket_name, key_name))
    s3_event = format_s3_event(s3_bucket_name, key_name)
    lambda_invoke_result = lambda_client.invoke(
        FunctionName=lambda_function_name,
        InvocationType="Event",
        Payload=json.dumps(s3_event),
    )
    if lambda_invoke_result["ResponseMetadata"]["HTTPStatusCode"] != 202:
        print("Error invoking lambda: {}".format(lambda_invoke_result))


# Format an S3 Event to use when invoking the lambda function
# https://docs.aws.amazon.com/AmazonS3/latest/dev/notification-content-structure.html
def format_s3_event(s3_bucket_name, key_name):
    s3_event = {
        "Records": [
            {"s3": {"bucket": {"name": s3_bucket_name}, "object": {"key": key_name}}}
        ]
    }
    return s3_event

def parse_date(timestamp):
    return datetime.utcfromtimestamp(timestamp)

def export_json(s3_object_list):
    
    f = open('file_export.json', 'w')

    f.write(json.dumps({"files": s3_object_list}))

    f.close
    print("Exported")

def main(lambda_function_name, s3_bucket_name, profile, limit, start_time=None, end_time=None, report=None, export_file=None):
    # Verify the lambda exists
    sess = boto3.session.Session(profile_name=profile)
    lambda_client = sess.client("lambda")
    try:
        lambda_client.get_function(FunctionName=lambda_function_name)
    except Exception:
        print("Lambda Function '{}' does not exist".format(lambda_function_name))
        sys.exit(1)

    if export_file:
        export = open(export_file, 'r')
        json_import = json.loads(export.read())["files"]
        for key_name in json_import:
            scan_object(lambda_client, lambda_function_name, s3_bucket_name, key_name)

    else:

        # Verify the S3 bucket exists
        s3_client = sess.client("s3")
        try:
            s3_client.head_bucket(Bucket=s3_bucket_name)
        except Exception:
            print("S3 Bucket '{}' does not exist".format(s3_bucket_name))
            sys.exit(1)

        if start_time:
            start_datetime = parse_date(start_time)

        if end_time:
            end_datetime = parse_date(end_time)

        # Scan the objects in the bucket
        s3_object_list = get_objects(s3_client, s3_bucket_name, limit, start_datetime, end_datetime)
        if limit:
            s3_object_list = s3_object_list[: min(limit, len(s3_object_list))]
            print(f"Final: Objects to be scanned: {len(s3_object_list)}")
        if not report:
            for key_name in s3_object_list:
                scan_object(lambda_client, lambda_function_name, s3_bucket_name, key_name)
        else:
            export_json(s3_object_list)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scan an S3 bucket for viruses.")
    parser.add_argument(
        "--lambda-function-name",
        required=True,
        help="The name of the lambda function to invoke",
    )
    parser.add_argument(
        "--s3-bucket-name", required=True, help="The name of the S3 bucket to scan"
    )
    parser.add_argument(
        "--profile", help="AWS profile to use", default="default"
    )
    parser.add_argument(
        "--limit", type=int, help="The number of records to limit to"
    )
    parser.add_argument(
        "--start-date", type=int, help="Start time: Epoch timestamp"
    )
    parser.add_argument(
        "--end-date", type=int, help="End time: Epoch timestamp"
    )
    parser.add_argument(
        "--report", action='store_true', help="Just generate a report"
    )
    parser.add_argument(
        "--export-file", type=str, help="Name of the export file to use"
    )

    args = parser.parse_args()

    main(args.lambda_function_name, args.s3_bucket_name, args.profile, 
        args.limit, start_time=args.start_date, end_time=args.end_date, 
        report=args.report, export_file=args.export_file)
