"""Define the CDK stack for the quantum-safe KDF workflow.

The stack sets up a Lambda function with basic execution permissions
and a Step Function that invokes the function with a 200-millisecond
timeout.
"""

from aws_cdk import Duration, Stack
from aws_cdk import aws_iam as iam
from aws_cdk import aws_lambda as lambda_
from aws_cdk import aws_stepfunctions as sfn
from aws_cdk import aws_stepfunctions_tasks as tasks
from constructs import Construct


class QsKdfStack(Stack):
    """Provision a Lambda and state machine for the quantum-safe KDF.

    The Lambda performs a KDF step and the Step Function limits execution
    to 200 milliseconds.
    """
    def __init__(self, scope: Construct, id: str, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

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
            code=lambda_.Code.from_asset("../build/lambda"),
            handler="qs_kdf.lambda_handler",
            role=lambda_role,
            timeout=Duration.seconds(10),
        )

        task = tasks.LambdaInvoke(self, "Invoke", lambda_function=func)
        sfn.StateMachine(
            self,
            "Workflow",
            definition=task.timeout(Duration.millis(200)),
        )
