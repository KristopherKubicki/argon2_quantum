import aws_cdk as cdk
from qs_kdf_stack import QsKdfStack

app = cdk.App()
QsKdfStack(app, "QsKdfStack")
app.synth()
