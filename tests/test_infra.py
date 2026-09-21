from pathlib import Path
import sys

import aws_cdk as cdk
from aws_cdk.assertions import Match, Template
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "infra"))
from qs_kdf_stack import QsKdfStack  # noqa: E402


def test_private_service_resources_and_permissions(tmp_path):
    (tmp_path / "handler.py").write_text("# synthetic asset for template assertions\n")
    app = cdk.App(context={"keyIds": ["k1", "k2"], "currentKeyId": "k2"})
    stack = QsKdfStack(app, "Test", asset_path=str(tmp_path))
    template = Template.from_stack(stack)
    template.resource_count_is("AWS::KMS::Key", 2)
    template.has_resource(
        "AWS::KMS::Key",
        {
            "DeletionPolicy": "Retain",
            "UpdateReplacePolicy": "Retain",
            "Properties": Match.object_like(
                {"KeySpec": "HMAC_256", "KeyUsage": "GENERATE_VERIFY_MAC"}
            ),
        },
    )
    template.has_resource_properties(
        "AWS::Lambda::Function",
        {
            "MemorySize": 512,
            "Timeout": 15,
            "ReservedConcurrentExecutions": 5,
            "Runtime": "python3.12",
            "Handler": "qs_kdf.service.lambda_handler",
            "Environment": {
                "Variables": Match.object_like({"QS_CURRENT_KEY_ID": "k2"})
            },
        },
    )
    template.resource_count_is("AWS::Lambda::Url", 0)
    template.resource_count_is("AWS::StepFunctions::StateMachine", 0)
    template.resource_count_is("AWS::CloudWatch::Alarm", 2)
    resources = template.to_json()["Resources"]
    statements = [
        s
        for r in resources.values()
        if r["Type"] == "AWS::IAM::Policy"
        for s in r["Properties"]["PolicyDocument"]["Statement"]
    ]
    kms_statements = [s for s in statements if s["Action"] == "kms:GenerateMac"]
    assert len(kms_statements) == 1
    assert isinstance(kms_statements[0]["Resource"], list)
    assert "*" not in kms_statements[0]["Resource"]
    app.synth()


@pytest.mark.parametrize("key_ids", [[], ["k1", "k1"], "k1", ["bad/id"]])
def test_invalid_rotation_config(tmp_path, key_ids):
    app = cdk.App(context={"keyIds": key_ids})
    with pytest.raises(ValueError):
        QsKdfStack(app, "Bad", asset_path=str(tmp_path))
