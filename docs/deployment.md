# Deploying the private KMS verifier

The CDK stack creates one Python 3.12 x86_64 Lambda, a retained HMAC_256 KMS key,
a retained log group, and CloudWatch error/throttle alarms. No Redis, Braket,
Step Functions, public HTTP endpoint, or Terraform module is required or supplied.
The Lambda uses 512 MiB, a 15-second timeout, and reserved concurrency 5.
Default Argon2 work uses 64 MiB. Tune capacity using measured workload results.

## Build and inspect

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
bash scripts/package_lambda.sh
cd infra
python app.py
# Install the AWS CDK CLI if needed; review the synthesized template/diff.
cdk diff
```

The Python app can synthesize without a globally installed CDK CLI. The package
script creates `build/lambda/` and `build/lambda.zip` using the locked AWS runtime
and the project's built wheel. The source directory is resolved independently of
the working directory. The artifact targets Linux x86_64 Python 3.12.

## Deploy

Use a dedicated AWS account/role and an explicit target account/region. After
reviewing the synthesized resources and costs, bootstrap that environment if
needed, then run `cdk deploy` from `infra/`. Deployment prints FunctionArn,
CurrentKeyId, KeyArns, and LogGroupName.

Grant only trusted application roles `lambda:InvokeFunction` on that function
ARN. The function's runtime role can generate MACs only with its configured keys.
Do not grant users or ordinary application clients `kms:GenerateMac`,
`kms:VerifyMac`, key administration, or direct invocation. Key administrators can
change access policy, so separate that role from application operators.

The application, not Lambda, persists the returned record in the correct user
row. Send passwords only over authenticated encrypted connections. Avoid CLI
arguments, logs, traces, SDK debug output, and Step Functions histories containing
passwords, raw Argon2 intermediates, or MAC requests. Use a trusted SDK caller to
invoke the private function. The service intentionally does not return its raw
Argon2 intermediate.

## Configuration and rotation

The deployed Lambda sets:

- `QS_KMS_KEYS`: JSON mapping logical key IDs to immutable KMS key ARNs.
- `QS_CURRENT_KEY_ID`: logical ID used for new records.

There is no `QS_PEPPER`, encrypted-pepper environment variable, or QPU ARN in
this service. Immutable key ARNs are required; aliases could redirect old records
to a different key and break verification.

`infra/cdk.json` initially sets `keyIds` to `["k1"]`, current ID `k1`. To rotate,
add `k2` while retaining `k1`, and set current ID to `k2`. The stack creates the
new key and authorizes both. Verify old records and replace them after successful
login. Do not remove the old key ID from the stack/config until live records and
restorable backups no longer need it. KMS keys are retained on removal, but
removing their runtime allowlist/IAM access still breaks verification.

Do not change key specifications or reuse an old logical ID for different key
material. Key and log retention prevents accidental deletion but still requires
an intentional recovery and cost-management process.

Alarms are created without notification destinations. Connect them to your
existing incident system and test delivery before launch. The stack does not
create an on-call subscription automatically.
