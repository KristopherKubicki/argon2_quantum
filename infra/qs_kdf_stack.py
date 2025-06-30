from aws_cdk import Duration, Stack
from aws_cdk import aws_dynamodb as dynamodb
from aws_cdk import aws_iam as iam
from aws_cdk import aws_kms as kms
from aws_cdk import aws_lambda as lambda_
from aws_cdk import aws_logs as logs
from aws_cdk import aws_elasticache as ec
from aws_cdk import aws_stepfunctions as sfn
from aws_cdk import aws_stepfunctions_tasks as tasks
from constructs import Construct


class QsKdfStack(Stack):
    def __init__(self, scope: Construct, id: str, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        _key = kms.Key(self, "PepperKey")
        lambda_role = iam.Role(
            self,
            "LambdaRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
        )
        lambda_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name(
                "service-role/AWSLambdaBasicExecutionRole"
            )
        )
        func = lambda_.Function(
            self,
            "Handler",
            runtime=lambda_.Runtime.PYTHON_3_11,
            code=lambda_.Code.from_asset("../"),
            handler="qs_kdf.lambda_handler",
            role=lambda_role,
            timeout=Duration.seconds(10),
        )

        _table = dynamodb.Table(
            self,
            "Digests",
            partition_key=dynamodb.Attribute(
                name="digest", type=dynamodb.AttributeType.STRING
            ),
            time_to_live_attribute="ttl",
        )

        _redis = ec.CfnServerlessCache(self, "Cache", engine="redis")

        _spend_alarm = logs.MetricFilter(
            self,
            "BraketSpendAlarm",
            log_group=logs.LogGroup(self, "Dummy"),
            metric_name="BraketSpend",
            metric_namespace="Billing",
            filter_pattern=logs.FilterPattern.all_terms("Braket"),
        )

        task = tasks.LambdaInvoke(self, "Invoke", lambda_function=func)
        sfn.StateMachine(
            self,
            "Workflow",
            definition=task.timeout(Duration.millis(200)),
        )
