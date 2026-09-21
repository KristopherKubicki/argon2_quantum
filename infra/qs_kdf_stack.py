"""Private password verifier with retained, non-exportable HMAC keys."""

from pathlib import Path
import re

from aws_cdk import CfnOutput, Duration, RemovalPolicy, Stack
from aws_cdk import aws_cloudwatch as cloudwatch
from aws_cdk import aws_iam as iam
from aws_cdk import aws_kms as kms
from aws_cdk import aws_lambda as lambda_
from aws_cdk import aws_logs as logs
from constructs import Construct


class QsKdfStack(Stack):
    def __init__(
        self, scope: Construct, construct_id: str, *, asset_path=None, **kwargs
    ):
        super().__init__(scope, construct_id, **kwargs)
        key_ids = self.node.try_get_context("keyIds")
        if key_ids is None:
            key_ids = ["k1"]
        current = self.node.try_get_context("currentKeyId")
        if (
            not isinstance(key_ids, list)
            or not 1 <= len(key_ids) <= 16
            or any(
                not isinstance(k, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", k)
                for k in key_ids
            )
            or len(set(key_ids)) != len(key_ids)
            or (current is not None and current not in key_ids)
        ):
            raise ValueError("keyIds must be unique IDs and include currentKeyId")
        if current is None:
            current = key_ids[-1]
        keys = {
            kid: kms.Key(
                self,
                f"Pepper-{kid}",
                key_spec=kms.KeySpec.HMAC_256,
                key_usage=kms.KeyUsage.GENERATE_VERIFY_MAC,
                removal_policy=RemovalPolicy.RETAIN,
                pending_window=Duration.days(30),
                description=f"QS pepper {kid}; retain until all records migrate",
            )
            for kid in key_ids
        }
        log_group = logs.LogGroup(
            self,
            "VerifierLogs",
            retention=logs.RetentionDays.ONE_MONTH,
            removal_policy=RemovalPolicy.RETAIN,
        )
        asset = asset_path or str(
            Path(__file__).resolve().parents[1] / "build" / "lambda"
        )
        func = lambda_.Function(
            self,
            "Handler",
            runtime=lambda_.Runtime.PYTHON_3_12,
            architecture=lambda_.Architecture.X86_64,
            code=lambda_.Code.from_asset(asset),
            handler="qs_kdf.service.lambda_handler",
            timeout=Duration.seconds(15),
            memory_size=512,
            reserved_concurrent_executions=5,
            log_group=log_group,
            environment={
                "QS_KMS_KEYS": self.to_json_string(
                    {kid: key.key_arn for kid, key in keys.items()}
                ),
                "QS_CURRENT_KEY_ID": current,
            },
        )
        func.add_to_role_policy(
            iam.PolicyStatement(
                actions=["kms:GenerateMac"],
                resources=[key.key_arn for key in keys.values()],
            )
        )
        for name, metric in (
            ("Errors", func.metric_errors()),
            ("Throttles", func.metric_throttles()),
        ):
            cloudwatch.Alarm(
                self,
                name,
                metric=metric,
                threshold=1,
                evaluation_periods=1,
                treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
            )
        CfnOutput(self, "FunctionArn", value=func.function_arn)
        CfnOutput(self, "CurrentKeyId", value=current)
        CfnOutput(
            self,
            "KeyArns",
            value=self.to_json_string({k: v.key_arn for k, v in keys.items()}),
        )
        CfnOutput(self, "LogGroupName", value=log_group.log_group_name)
