# from rest_framework_simplejwt.tokens import RefreshToken
# from .serializers import CustomUserSerializer

# def get_auth_for_user(user):
#     tokens = RefreshToken.for_user(user)
#     return {
#         'user': CustomUserSerializer(user).data,
#         'tokens': {
#             'access': str(tokens.access_token),
#             'refresh': str(tokens),
#         }
#     }
