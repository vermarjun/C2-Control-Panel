import grpc
import os
from generated.rpcpb import services_pb2, services_pb2_grpc
from generated.commonpb import common_pb2
from generated.clientpb import client_pb2

# Configs
SLIVER_HOST = "192.168.231.123"
SLIVER_PORT = 31337
TOKEN = "a1b4e76484e4409b29ac204d9030f61a41c882119acc818a0ab329ede14c4495"

current_dir = os.path.dirname(os.path.abspath(__file__))

certificatechain_filepath = os.path.join(current_dir, 'certificate.crt')

rootcertificates_filepath = os.path.join(current_dir, 'ca_certificate.crt')

privatekey_filepath = os.path.join(current_dir, 'private_key.key')

# Load SSL credentials
with open(certificatechain_filepath, 'rb') as f:
    certificate_chain = f.read()

with open(rootcertificates_filepath, 'rb') as f:
    root_certificates = f.read()

with open(privatekey_filepath, 'rb') as f:
    private_key = f.read()

# Create SSL credentials for the gRPC channel
creds = grpc.ssl_channel_credentials(
    root_certificates=root_certificates,
    private_key=private_key,
    certificate_chain=certificate_chain
)

# Add token to metadata using an interceptor
class TokenInterceptor(grpc.UnaryUnaryClientInterceptor):
    def __init__(self, token):
        self.token = token

    def intercept_unary_unary(self, continuation, client_call_details, request):
        metadata = []
        if client_call_details.metadata is not None:
            metadata = list(client_call_details.metadata)
        metadata.append(('authorization', f'Bearer {self.token}'))

        client_call_details = client_call_details._replace(metadata=metadata)
        return continuation(client_call_details, request)

interceptor = TokenInterceptor(TOKEN)

options = (
    ("grpc.ssl_target_name_override", "multiplayer"),
)

# Create secure gRPC channel with interceptor
channel = grpc.secure_channel(f"{SLIVER_HOST}:{SLIVER_PORT}", creds, options)
intercept_channel = grpc.intercept_channel(channel, interceptor)

# Create stub
stub = services_pb2_grpc.SliverRPCStub(intercept_channel)

# Call GetOperators method
try:
    response = stub.GetOperators(common_pb2.Empty())
    print("Operators:", response)
except grpc.RpcError as e:
    print(f"RPC Error: {e.code()} - {e.details()}")
