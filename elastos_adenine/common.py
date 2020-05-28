import grpc
import jwt
import datetime
import json

from .stubs import common_pb2, common_pb2_grpc
from elastos_adenine.settings import REQUEST_TIMEOUT, TOKEN_EXPIRATION, GRPC_MAX_MSG_SIZE


class Common:

    def __init__(self, host, port, production):
        if not production:
            self._channel = grpc.insecure_channel('{}:{}'.format(host, port), options=[
                  ('grpc.max_send_message_length', GRPC_MAX_MSG_SIZE),
                  ('grpc.max_receive_message_length', GRPC_MAX_MSG_SIZE)
            ])
        else:
            credentials = grpc.ssl_channel_credentials()
            self._channel = grpc.secure_channel('{}:{}'.format(host, port), credentials, options=[
                  ('grpc.max_send_message_length', GRPC_MAX_MSG_SIZE),
                  ('grpc.max_receive_message_length', GRPC_MAX_MSG_SIZE)
            ])
        
        self.stub = common_pb2_grpc.CommonStub(self._channel)

    def close(self):
        self._channel.close()

    def generate_api_request(self, secret_key, did):
        jwt_info = {}

        jwt_token = jwt.encode({
            'jwt_info': jwt_info,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=TOKEN_EXPIRATION)
        }, secret_key, algorithm='HS256')

        response = self.stub.GenerateAPIRequest(common_pb2.Request(input=jwt_token), timeout=REQUEST_TIMEOUT, metadata=[('did', did)])
        
        if response.status:
            output = jwt.decode(response.output, key=secret_key, algorithms=['HS256']).get('jwt_info')
            result = {
                'output': json.dumps(output),
                'status_message': response.status_message,
                'status': response.status
            }
        else:
            result = {
                'output': '',
                'status_message': response.status_message,
                'status': response.status
            }
        return result

    def get_api_key_request(self, secret_key, did):
        jwt_info = {}

        jwt_token = jwt.encode({
            'jwt_info': jwt_info,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=TOKEN_EXPIRATION)
        }, secret_key, algorithm='HS256')

        response = self.stub.GetAPIKey(common_pb2.Request(input=jwt_token), timeout=REQUEST_TIMEOUT, metadata=[('did', did)])
        
        if response.status:
            output = jwt.decode(response.output, key=secret_key, algorithms=['HS256']).get('jwt_info')
            result = {
                'output': json.dumps(output),
                'status_message': response.status_message,
                'status': response.status
            }
        else:
            result = {
                'output': '',
                'status_message': response.status_message,
                'status': response.status
            }
        return result
