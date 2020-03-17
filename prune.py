#!/usr/bin/env python3

from __future__ import absolute_import, print_function, unicode_literals
import boto3
import argparse
from pprint import pprint

def main():
    client = lambda_client(command_line_arguments().account)
    [prune_function(client, function) for function
      in client.list_functions()['Functions']]


def prune_function(client, function):
    print(f"Pruning '{function['FunctionName']}'.")
    versions = client.list_versions_by_function(
        FunctionName=function['FunctionArn'])['Versions']
    old_arns = [v['FunctionArn'] for v in [version for version in versions
                                           if version['Version'] !=
                                           function['Version']]]

    [remove_version(client, arn) for arn in old_arns]

def remove_version(client, arn):
    print(f"Deleting '{arn}'.")
    client.delete_function(FunctionName=arn)

def lambda_client(account):
    sts  = boto3.client('sts')
    credentials = sts.assume_role(
        RoleArn=f"arn:aws:iam::{account}:role/ci",
        RoleSessionName='clean_up')['Credentials']
    return boto3.client('lambda',
                        aws_access_key_id=credentials['AccessKeyId'],
                        aws_secret_access_key=credentials['SecretAccessKey'],
                        aws_session_token=credentials['SessionToken'])

def command_line_arguments():
    parser = argparse.ArgumentParser(
        description='Delete all but the latest version of a lambda.')
    parser.add_argument('account', help='The account to target')
    return parser.parse_args()

if __name__ == '__main__':
    main()
