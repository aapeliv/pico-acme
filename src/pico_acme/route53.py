from time import sleep

import boto3


def route53_upsert_cleanup(hosted_zone_id, **boto3_kwargs):
    r53 = boto3.client("route53", **boto3_kwargs)

    def wait_for_dns_change(change_id):
        for _ in range(0, 120):
            response = r53.get_change(Id=change_id)
            if response["ChangeInfo"]["Status"] == "INSYNC":
                return
            sleep(2)
        raise Exception(f'Timed out waiting for Route53 change. Current status: {response["ChangeInfo"]["Status"]}')

    def upsert_dns01_record(record, value):
        res = r53.change_resource_record_sets(
            HostedZoneId=hosted_zone_id,
            ChangeBatch={
                "Changes": [
                    {
                        "Action": "UPSERT",
                        "ResourceRecordSet": {
                            "Name": record,
                            "Type": "TXT",
                            "TTL": 60,
                            "ResourceRecords": [
                                {
                                    "Value": f'"{value}"',
                                },
                            ],
                        },
                    },
                ]
            },
        )
        wait_for_dns_change(res["ChangeInfo"]["Id"])

    def delete_dns_challenge_record(record, value):
        return r53.change_resource_record_sets(
            HostedZoneId=hosted_zone_id,
            ChangeBatch={
                "Changes": [
                    {
                        "Action": "DELETE",
                        "ResourceRecordSet": {
                            "Name": record,
                            "Type": "TXT",
                            "TTL": 60,
                            "ResourceRecords": [
                                {
                                    "Value": f'"{value}"',
                                },
                            ],
                        },
                    },
                ]
            },
        )

    return upsert_dns01_record, delete_dns_challenge_record
