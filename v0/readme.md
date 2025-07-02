arjun.crt should have => certificate

arjun.key should have => private key

ca.crt should have => ca_certificate


protobuf folder is from the bishopfox github sliver repository, just download the repo and copy that folder here.

After copying that folder create a generate folder in root directory like I created inside v0

after that just run this command (make sure you're inside protobuf folder while running it): 

python -m grpc_tools.protoc -I. --python_out=../generated --grpc_python_out=../generated commonpb/common.proto clientpb/client.proto rpcpb/services.proto sliverpb/sliver.proto dnspb/dns.proto

This command will use protofiles in protobuf folder and compile them to python Python using protoc tool in grpc_tools

Make sure that here:
1) root_certificates = ca_certificate.crt
2) private_key = private_key.key
3) certificate_chain = certificate.crt



