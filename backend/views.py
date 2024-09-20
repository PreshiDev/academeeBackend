from django.shortcuts import render
from django.contrib.auth import get_user_model
from rest_framework import status, permissions, viewsets, exceptions
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.authtoken.models import Token
from rest_framework.views import APIView
from rest_framework import serializers
from django.contrib.auth import authenticate
from django.conf import settings
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt  # Only use for this specific view
from django.middleware.csrf import get_token
from .serializers import UserSerializer, ReportSheetSerializer, WorkBookSerializer, SchoolActivitiesSerializer, AssemblyTopicSerializer, ClassNoteSerializer, ReportCommentSerializer, SchemeWorkSerializer, LessonNoteSerializer, ExamQuestionSerializer, ExamTimetableSerializer, LoginSerializer, NotificationSerializer, NewsHeadlineSerializer, SchoolCalendarSerializer, ChatMessageSerializer, VideoCommentSerializer, ChatMessageReplySerializer, UserDetailSerializer, UserUpdateSerializer, CustomTokenObtainPairSerializer, AnnouncementSerializer, SchoolPoliciesSerializer, GraduationSerializer, NewsCommentSerializer # Assuming you have a UserSerializer class
from .models import CustomToken, SchoolCalendar, ChatMessage, VideoComment, CustomUser, Notification, SchemeWork, LessonNote, ExamQuestion, ExamTimetable, ClassNote, ReportComment, AssemblyTopic, SchoolActivities, WorkBooks, ReportSheet, Announcement, SchoolPolicies, Graduation, NewsComment
from rest_framework import generics
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import ensure_csrf_cookie
import logging
import jwt
import datetime
from django.views.generic import ListView, DetailView, CreateView, UpdateView, DeleteView
from django.urls import reverse_lazy
from .models import NewsHeadline
from django.contrib import admin
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.permissions import IsAuthenticated
from rest_framework import generics, permissions
from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import IsAuthenticatedOrReadOnly
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from django.utils import timezone
from datetime import timedelta
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.core.mail import send_mail
from paystackapi.transaction import Transaction
from django.conf import settings
from datetime import date
# from google.oauth2 import service_account
# from googleapiclient.discovery import build
#from .utils import get_auth_for_user  # Import your custom function


logger = logging.getLogger(__name__)
User = get_user_model()

JWT_SECRET_KEY = "secret1234.@"

@api_view(['POST'])
@permission_classes([AllowAny])
def register_view(request):
    if request.method == 'POST':
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    return Response({'error': 'Method not allowed'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)


class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer

    def post(self, request, *args, **kwargs):
        print("OKKKKKKKKAYYYY")
        response = super().post(request, *args, **kwargs)
        refresh = response.data['refresh']
        access = response.data['access']
        token_expiry = RefreshToken(refresh).access_token.payload['exp']
        response.data['access_token_expiry'] = token_expiry

        # Decode the access token and log the payload
        access_token_payload = jwt.decode(access, settings.SECRET_KEY, algorithms=['HS256'])
        logger.debug(f"Access token payload: {access_token_payload}")

        return response

@method_decorator(ensure_csrf_cookie, name='dispatch')
class LoginView(APIView):
    permission_classes = []

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data['user']
            token, created = CustomToken.objects.get_or_create(user=user)

            # Create JWT token
            access_token = RefreshToken.for_user(user).access_token
            refresh_token = str(RefreshToken.for_user(user))

            response = Response({
                'access_token': str(access_token),
                'refresh_token': refresh_token,
                'is_active': user.is_active,
                'is_staff': user.is_staff,
                'is_superuser': user.is_superuser
            }, status=status.HTTP_200_OK)

            # Set the token in the authorization header
            response['Authorization'] = f'Bearer {access_token}'

            return response
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
                

class GetCSRFToken(APIView):
    permission_classes = [permissions.AllowAny]

    def get(self, request):
        csrf_token = get_token(request)
        return JsonResponse({'csrfToken': csrf_token})
    
class NotificationListView(generics.ListAPIView):
    queryset = Notification.objects.all().order_by('-created_at')
    serializer_class = NotificationSerializer

class NotificationCreateView(generics.CreateAPIView):
    serializer_class = NotificationSerializer

    def perform_create(self, serializer):
        notification = serializer.save()

        # Get all users
        users = CustomUser.objects.all()

        # Send an email to each user
        for user in users:
            if user.email:  # Ensure the user has an email address
                send_mail(
                    subject=f"New Notification: {notification.title}",
                    message=notification.message,
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    recipient_list=[user.email],
                    fail_silently=False,
                )

class ResetNotificationCountView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def post(self, request, *args, **kwarg):
        id = self.kwargs.get('id')
        notifications = Notification.objects.filter(id=id)
        notifications.update(is_read=True)  # Assuming you have an `is_read` field to track read status
        return Response({'status': 'notification count reset'})

class LatestNewsListView(generics.ListAPIView):
    queryset = NewsHeadline.objects.filter(is_published=True).order_by('-published_date')  # Limit to 4 latest news
    serializer_class = NewsHeadlineSerializer

class AllNewsListView(generics.ListAPIView):
    queryset = NewsHeadline.objects.filter(is_published=True).order_by('-published_date')
    serializer_class = NewsHeadlineSerializer

class News(generics.ListAPIView):
    serializer_class = NewsHeadlineSerializer
    
    def get_queryset(self):
        id = self.kwargs.get('id')
        print("ID", id)
        return NewsHeadline.objects.filter(id=id, is_published=True)

class NewsCreateView(generics.CreateAPIView):
    queryset = NewsHeadline.objects.all()
    serializer_class = NewsHeadlineSerializer
    permission_classes = [permissions.AllowAny]

    def perform_create(self, serializer):
        news_headline = serializer.save()
        # Create a notification
        Notification.objects.create(
            title="New News Headline",
            message=f"A new headline has been created: {news_headline.title}",
            user=self.request.user  # Adjust this according to your user model and authentication
        )

class SchoolCalendarListView(APIView):
    permission_classes = [IsAuthenticated]  # Ensure only authenticated users can access this view

    def get(self, request):
        calendars = SchoolCalendar.objects.all()
        serializer = SchoolCalendarSerializer(calendars, many=True, context={'request': request})
        return Response(serializer.data)

    def post(self, request):
        serializer = SchoolCalendarSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            calendar = serializer.save()
            # Create a notification
            Notification.objects.create(
                title="New School Calendar",
                message=f"A new calendar event has been created: {calendar.title}",
                user=request.user  # Adjust this according to your user model and authentication
            )
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class SchemeWorkListView(APIView):
    permission_classes = [IsAuthenticated]  # Ensure only authenticated users can access this view

    def get(self, request):
        schemework = SchemeWork.objects.all()
        serializer = SchemeWorkSerializer(schemework, many=True, context={'request': request})
        return Response(serializer.data)

    def post(self, request):
        serializer = SchemeWorkSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            scheme = serializer.save()
            # Create a notification
            Notification.objects.create(
                title="New School Calendar",
                message=f"A new calendar event has been created: {scheme.title}",
                user=request.user  # Adjust this according to your user model and authentication
            )
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class LessonNoteView(APIView):
    permission_classes = [IsAuthenticated]  # Ensure only authenticated users can access this view

    def get(self, request):
        lessonnote = LessonNote.objects.all()
        serializer = LessonNoteSerializer(lessonnote, many=True, context={'request': request})
        return Response(serializer.data)

    def post(self, request):
        serializer = LessonNoteSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            lesson = serializer.save()
            # Create a notification
            Notification.objects.create(
                title="New Lesson Note",
                message=f"A new lesson note has been uploaded: {lesson.title}",
                user=request.user  # Adjust this according to your user model and authentication
            )
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class TermClassChoicesView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        term_choices = [{'value': choice[0], 'label': choice[1]} for choice in LessonNote.TERM_CHOICES]
        class_choices = [{'value': choice[0], 'label': choice[1]} for choice in LessonNote.CLASS_CHOICES]
        return Response({'term_choices': term_choices, 'class_choices': class_choices})
    
class ExamQuestionView(APIView):
    permission_classes = [IsAuthenticated]  # Ensure only authenticated users can access this view

    def get(self, request):
        examquestion = ExamQuestion.objects.all()
        serializer = ExamQuestionSerializer(examquestion, many=True, context={'request': request})
        return Response(serializer.data)

    def post(self, request):
        serializer = ExamQuestionSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            questions = serializer.save()
            # Create a notification
            Notification.objects.create(
                title="New Exam Questions",
                message=f"A new exam questions has been uploaded: {questions.title}",
                user=request.user  # Adjust this according to your user model and authentication
            )
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class ExamTermClassChoicesView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        term_choices = [{'value': choice[0], 'label': choice[1]} for choice in ExamQuestion.TERM_CHOICES]
        class_choices = [{'value': choice[0], 'label': choice[1]} for choice in ExamQuestion.CLASS_CHOICES]
        return Response({'term_choices': term_choices, 'class_choices': class_choices})


class AvailableYearsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        current_year = date.today().year
        # Generate years dynamically from the current year going back a few years
        years = list(range(current_year - 10, current_year + 1))  # Adjust range as needed
        return Response({'years': years})


class ExamTimetableView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        year = request.query_params.get('year')
        if year:
            examtimetable = ExamTimetable.objects.filter(year=year)
        else:
            examtimetable = ExamTimetable.objects.all()
        serializer = ExamTimetableSerializer(examtimetable, many=True, context={'request': request})
        return Response(serializer.data)

    def post(self, request):
        serializer = ExamTimetableSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            timetable = serializer.save()
            Notification.objects.create(
                title="New Exam Timetable",
                message=f"A new exam timetable has been uploaded: {timetable.title}",
                user=request.user
            )
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


    
class ClassNoteView(APIView):
    permission_classes = [IsAuthenticated]  # Ensure only authenticated users can access this view

    def get(self, request):
        classnote = ClassNote.objects.all()
        serializer = ClassNoteSerializer(classnote, many=True, context={'request': request})
        return Response(serializer.data)

    def post(self, request):
        serializer = ClassNoteSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            classnotes = serializer.save()
            # Create a notification
            Notification.objects.create(
                title="New Class Note",
                message=f"A new class note has been uploaded: {classnotes.title}",
                user=request.user  # Adjust this according to your user model and authentication
            )
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class ReportCommentView(APIView):
    permission_classes = [IsAuthenticated]  # Ensure only authenticated users can access this view

    def get(self, request):
        reportcomment = ReportComment.objects.all()
        serializer = ReportCommentSerializer(reportcomment, many=True, context={'request': request})
        return Response(serializer.data)

    def post(self, request):
        serializer = ReportCommentSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            reportcomments = serializer.save()
            # Create a notification
            Notification.objects.create(
                title="New Report Card Comments",
                message=f"A new report card comment has been uploaded: {reportcomments.title}",
                user=request.user  # Adjust this according to your user model and authentication
            )
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class AssemblyTopicView(APIView):
    permission_classes = [IsAuthenticated]  # Ensure only authenticated users can access this view

    def get(self, request):
        assemblytopic = AssemblyTopic.objects.all()
        serializer = AssemblyTopicSerializer(assemblytopic, many=True, context={'request': request})
        return Response(serializer.data)

    def post(self, request):
        serializer = AssemblyTopicSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            assemblytopics = serializer.save()
            # Create a notification
            Notification.objects.create(
                title="New Assembly Topics",
                message=f"A new assembly topics has been uploaded: {assemblytopics.title}",
                user=request.user  # Adjust this according to your user model and authentication
            )
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class SchoolActivityChoicesView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        activity_choices = [{'value': choice[0], 'label': choice[1]} for choice in SchoolActivities.ACTIVITIES]
        return Response({'activity_choices': activity_choices})

class SchoolActivitiesView(APIView):
    permission_classes = [IsAuthenticated]  # Ensure only authenticated users can access this view

    def get(self, request):
        schoolactivity = SchoolActivities.objects.all()
        serializer = SchoolActivitiesSerializer(schoolactivity, many=True, context={'request': request})
        return Response(serializer.data)

    def post(self, request):
        serializer = SchoolActivitiesSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            schoolactivities = serializer.save()
            # Create a notification
            Notification.objects.create(
                title="New School Activites",
                message=f"A new school activites has been uploaded: {schoolactivities.title}",
                user=request.user  # Adjust this according to your user model and authentication
            )
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class WorkBookView(APIView):
    permission_classes = [IsAuthenticated]  # Ensure only authenticated users can access this view

    def get(self, request):
        workbook = WorkBooks.objects.all()
        serializer = WorkBookSerializer(workbook, many=True, context={'request': request})
        return Response(serializer.data)

    def post(self, request):
        serializer = WorkBookSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            workbooks = serializer.save()
            # Create a notification
            Notification.objects.create(
                title="New Work Book",
                message=f"A new work book has been uploaded: {workbooks.title}",
                user=request.user  # Adjust this according to your user model and authentication
            )
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



class ReportSheetView(APIView):
    permission_classes = [IsAuthenticated]  # Ensure only authenticated users can access this view

    def get(self, request):
        reportsheet = ReportSheet.objects.all()
        serializer = ReportSheetSerializer(reportsheet, many=True, context={'request': request})
        return Response(serializer.data)

    def post(self, request):
        serializer = ReportSheetSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            reportsheets = serializer.save()
            # Create a notification
            Notification.objects.create(
                title="New Report Sheets Template",
                message=f"A new Report Sheets Template has been created: {reportsheets.title}",
                user=request.user  # Adjust this according to your user model and authentication
            )
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)




# class ChatMessageListCreateAPIView(generics.ListCreateAPIView):
#     queryset = ChatMessage.objects.filter(parent=None).order_by('-created_at')
#     serializer_class = ChatMessageSerializer
#     permission_classes = [permissions.AllowAny]

#     def perform_create(self, serializer):
#         user = self.request.user if self.request.user.is_authenticated else None
#         serializer.save(user=user)


class ChatMessageListCreateAPIView(generics.ListCreateAPIView):
    queryset = ChatMessage.objects.all()
    serializer_class = ChatMessageSerializer
    permission_classes = [permissions.AllowAny]

    def perform_create(self, serializer):
        print("Creating new chat message...")
        print("User:", self.request.user)
        
        try:
            if serializer.is_valid():
                serializer.save(user=self.request.user)
                print("Message saved successfully.")
            else:
                print("Validation errors:", serializer.errors)
                raise ValueError("Serializer validation failed.")
        except Exception as e:
            print(f"Error saving message: {e}")
            raise

    def post(self, request, *args, **kwargs):
        print("Received POST request data:", request.data)
        return super().post(request, *args, **kwargs)

class ChatReplyCreateAPIView(generics.CreateAPIView):
    serializer_class = ChatMessageReplySerializer
    permission_classes = [permissions.AllowAny]

    def perform_create(self, serializer):
        parent_id = self.kwargs.get('parent_id')
        print(f"Creating reply to message with id={parent_id}")
        
        try:
            parent = ChatMessage.objects.get(id=parent_id)
            print("Parent message found:", parent)
            serializer.save(user=self.request.user, parent=parent)
        except ChatMessage.DoesNotExist:
            print(f"Parent message with id={parent_id} does not exist")
            raise

    def post(self, request, *args, **kwargs):
        print("Received POST request data:", request.data)
        return super().post(request, *args, **kwargs)

class ChatMessageReplyListAPIView(generics.ListAPIView):
    serializer_class = ChatMessageSerializer
    permission_classes = [permissions.AllowAny]

    def get_queryset(self):
        parent_id = self.kwargs.get('parent_id')
        print(f"Fetching replies for message with id={parent_id}")
        
        queryset = ChatMessage.objects.filter(parent_id=parent_id).order_by('created_at')
        print("Queryset:", queryset)
        return queryset

    def list(self, request, *args, **kwargs):
        print("Received GET request with params:", kwargs)
        return super().list(request, *args, **kwargs)
    

class VideoCommentListCreateView(generics.ListCreateAPIView):
    serializer_class = VideoCommentSerializer
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]  # Allow read-only access to unauthenticated users

    def get_queryset(self):
        video_id = self.request.query_params.get('video_id')
        if video_id:
            return VideoComment.objects.filter(video_id=video_id).order_by('-created_at')
        return VideoComment.objects.none()

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)  # Save the user who made the comment

    def create(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return Response({'detail': 'Authentication credentials were not provided.'}, status=403)
        return super().create(request, *args, **kwargs)


class NewsCommentListCreateView(generics.ListCreateAPIView):
    serializer_class = NewsCommentSerializer
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]

    def get_queryset(self):
        news_id = self.request.query_params.get('news_id')
        if news_id:
            return NewsComment.objects.filter(news__id=news_id).order_by('-created_at')
        return NewsComment.objects.none()

    def perform_create(self, serializer):
        # Save the comment with the current user and the associated news article
        news_id = self.request.data.get('news_id')
        if news_id:
            news = NewsHeadline.objects.get(id=news_id)
            serializer.save(user=self.request.user, news=news)
        else:
            raise serializers.ValidationError("News ID is required.")

    # No need for a custom create method, as the permission class handles authentication



# class CustomTokenObtainPairView(TokenObtainPairView):
#     permission_classes = (AllowAny,)

#     def post(self, request, *args, **kwargs):
#         print("Okayyyyyyyyyy")
#         response = super().post(request, *args, **kwargs)
#         refresh = response.data['refresh']
#         access = response.data['access']
#         token_expiry = RefreshToken(refresh).access_token.payload['exp']
#         response.data['access_token_expiry'] = token_expiry
#         return response

class CustomTokenRefreshView(TokenRefreshView):
    permission_classes = (AllowAny,)

    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)
        access = response.data['access']
        token_expiry = RefreshToken(access).payload['exp']
        response.data['access_token_expiry'] = token_expiry
        return response

@api_view(['GET'])
def user_detail_view(request):
    try:
        user = User.objects.all()  # Adjust this line to match your actual logic
        serializer = UserDetailSerializer(user)
        return Response(serializer.data, status=status.HTTP_200_OK)
    except User.DoesNotExist:
        return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
    


class UserUpdateView(generics.UpdateAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = UserUpdateSerializer

    def get_object(self):
        return self.request.user

    def update(self, request, *args, **kwargs):
        logger.debug(f"Request data: {request.data}")
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        logger.debug(f"User instance: {instance}")

        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        if serializer.is_valid():
            self.perform_update(serializer)
            if getattr(instance, '_prefetched_objects_cache', None):
                instance._prefetched_objects_cache = {}
            return Response(serializer.data)
        else:
            logger.error(f"Validation errors: {serializer.errors}")
            print(f"Validation errors: {serializer.errors}")  # Print to console for easier debugging
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



def get_user_from_token(request):
    auth_header = request.META.get('HTTP_AUTHORIZATION')
    print(f"auth:  {auth_header}")
    if not auth_header:
        raise exceptions.AuthenticationFailed('Authorization header missing')

    # Assuming the header is in the format 'Bearer <token>'
    try:
        token = auth_header.split(' ')[1]
    except IndexError:
        raise exceptions.AuthenticationFailed('Invalid Authorization header format')

    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        raise exceptions.AuthenticationFailed('Token has expired')
    except jwt.InvalidTokenError:
        raise exceptions.AuthenticationFailed('Invalid token')

    user_id = payload.get('user_id')
    if not user_id:
        raise exceptions.AuthenticationFailed('Invalid token payload')

    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        raise exceptions.AuthenticationFailed('User not found')

    return user


    
class UserViewSet(generics.RetrieveUpdateAPIView):
    queryset = CustomUser.objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self):
        print(self.request)
        print(self.request.user)
        print(dir(self.request))
        return self.request.user
    # def update(self, request):
    #     user = get_user_from_token(request)
    #     serializer = UserDetailSerializer(user, data=request.data, partial=True)
    #     if serializer.is_valid():
    #         serializer.save()
    #         return Response(serializer.data)
    #     print(f"Serializer errors: {serializer.errors}")
    #     return Response(serializer.errors, status=400)

class SubscribeView(generics.UpdateAPIView):
    queryset = CustomUser.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]

    def initialize_payment(self, user, plan):
        plan_costs = {
            'monthly': 1000,  # Naira
            'quarterly': 2500,  # Naira
            'annually': 9000,  # Naira
        }

        if plan not in plan_costs:
            return None, {"detail": "Invalid subscription plan"}, status.HTTP_400_BAD_REQUEST

        # Initialize Paystack transaction
        paystack_secret_key = settings.PAYSTACK_SECRET_KEY
        transaction = Transaction(authorization_key=paystack_secret_key)

        response = transaction.initialize(
            reference=f"{user.id}_{timezone.now().timestamp()}",
            email=user.email,
            amount=plan_costs[plan] * 100  # Amount in kobo
        )

        if response['status']:
            return response['data'], None, None
        return None, {"detail": "Payment initialization failed"}, status.HTTP_400_BAD_REQUEST

    def verify_payment(self, reference):
        paystack_secret_key = settings.PAYSTACK_SECRET_KEY
        transaction = Transaction(authorization_key=paystack_secret_key)

        response = transaction.verify(reference)

        if response['status']:
            return response['data']
        return None

    def perform_update(self, user, plan):
        plan_durations = {
            'monthly': timedelta(days=30),
            'quarterly': timedelta(days=90),
            'annually': timedelta(days=365),
        }

        end_date = timezone.now() + plan_durations[plan]
        user.subscription_plan = plan
        user.subscription_start_date = timezone.now()
        user.subscription_end_date = end_date
        user.save()

    def update(self, request, *args, **kwargs):
        user = self.request.user
        plan = request.data.get('subscription_plan')

        if not plan:
            return Response({"detail": "Subscription plan is required"}, status=status.HTTP_400_BAD_REQUEST)

        # Check if payment_reference is in request
        payment_reference = request.data.get('payment_reference')

        if payment_reference:
            payment_data = self.verify_payment(payment_reference)

            if not payment_data:
                return Response({"detail": "Payment verification failed"}, status=status.HTTP_400_BAD_REQUEST)

            self.perform_update(user, plan)

            # Create a notification
            Notification.objects.create(
                title="Subscription Successful",
                message=f"You have successfully subscribed to the {plan} plan.",
                user=user
            )

            serializer = self.get_serializer(user)
            return Response(serializer.data)

        # Initialize payment if no payment_reference
        payment_data, error, status_code = self.initialize_payment(user, plan)
        if error:
            return Response(error, status=status_code)

        return Response({
            "payment_url": payment_data['authorization_url'],
            "reference": payment_data['reference']
        })
    

# class SubscribeView(generics.UpdateAPIView):
#     queryset = CustomUser.objects.all()
#     serializer_class = UserSerializer
#     permission_classes = [IsAuthenticated]

#     def verify_purchase(self, purchase_token):
#         # Google Play API credentials and settings
#         SCOPES = ['https://www.googleapis.com/auth/androidpublisher']
#         SERVICE_ACCOUNT_FILE = 'path/to/your/service-account-file.json'

#         credentials = service_account.Credentials.from_service_account_file(
#             SERVICE_ACCOUNT_FILE, scopes=SCOPES
#         )
#         service = build('androidpublisher', 'v3', credentials=credentials)

#         try:
#             # Replace 'your.package.name' with your app's package name
#             purchase = service.purchases().subscriptions().get(
#                 packageName='your.package.name',
#                 subscriptionId='your.subscription.id',
#                 token=purchase_token
#             ).execute()

#             if purchase.get('paymentState') == 1:
#                 return purchase
#             return None
#         except Exception as e:
#             print(f"Error verifying purchase: {e}")
#             return None

#     def perform_update(self, user, plan):
#         plan_durations = {
#             'monthly': timedelta(days=30),
#             'quarterly': timedelta(days=90),
#             'annually': timedelta(days=365),
#         }

#         end_date = timezone.now() + plan_durations[plan]
#         user.subscription_plan = plan
#         user.subscription_start_date = timezone.now()
#         user.subscription_end_date = end_date
#         user.save()

#     def update(self, request, *args, **kwargs):
#         user = self.request.user
#         plan = request.data.get('subscription_plan')
#         purchase_token = request.data.get('purchase_token')

#         if not plan:
#             return Response({"detail": "Subscription plan is required"}, status=status.HTTP_400_BAD_REQUEST)

#         if purchase_token:
#             purchase_data = self.verify_purchase(purchase_token)

#             if not purchase_data:
#                 return Response({"detail": "Purchase verification failed"}, status=status.HTTP_400_BAD_REQUEST)

#             self.perform_update(user, plan)

#             # Create a notification
#             Notification.objects.create(
#                 title="Subscription Successful",
#                 message=f"You have successfully subscribed to the {plan} plan.",
#                 user=user
#             )

#             serializer = self.get_serializer(user)
#             return Response(serializer.data)

#         # You could also initialize subscription on the frontend if needed
#         return Response({"detail": "Purchase token is required for verification"})



class AnnouncementListView(generics.ListAPIView):
    queryset = Announcement.objects.all().order_by('-created_at')
    serializer_class = AnnouncementSerializer

class AnnouncementCreateView(generics.CreateAPIView):
    permission_classes = [IsAuthenticated]  # Ensure only authenticated users can access this view
    serializer_class = AnnouncementSerializer

    def perform_create(self, serializer):
        # Save the announcement instance
        announcement = serializer.save()

        # Create a notification with the announcement's details
        Notification.objects.create(
            title="New Announcement",
            message=f"New announcement created: {announcement.title}\n\n{announcement.message}",
            user=self.request.user  # Adjust this according to your user model and authentication
        )

def get_counts(request):
    counts = {
        "user_count": CustomUser.objects.count(),
        "subscribed_user_count": CustomUser.objects.filter(subscription_plan__in=['monthly', 'quarterly', 'annually']).count(),
        "work_book_count": WorkBooks.objects.count(),
        "lesson_note_count": LessonNote.objects.count(),
        "news_headline_count": NewsHeadline.objects.count(),
        "school_calendar_count": SchoolCalendar.objects.count(),
        "scheme_work_count": SchemeWork.objects.count(),
        "exam_question_count": ExamQuestion.objects.count(),
        "exam_timetable_count": ExamTimetable.objects.count(),
        "class_note_count": ClassNote.objects.count(),
        "report_comment_count": ReportComment.objects.count(),
        "assembly_topic_count": AssemblyTopic.objects.count(),
        "school_activities_count": SchoolActivities.objects.count(),
        "report_sheet_count": ReportSheet.objects.count(),
        "announcement_count": Announcement.objects.count(),
    }
    return JsonResponse(counts)

class SchoolPoliciesView(APIView):
    permission_classes = [IsAuthenticated]  # Ensure only authenticated users can access this view

    def get(self, request):
        classnote = SchoolPolicies.objects.all()
        serializer = SchoolPoliciesSerializer(classnote, many=True, context={'request': request})
        return Response(serializer.data)

    def post(self, request):
        serializer = SchoolPoliciesSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            classnotes = serializer.save()
            # Create a notification
            Notification.objects.create(
                title="New Class Note",
                message=f"A new class note has been uploaded: {classnotes.title}",
                user=request.user  # Adjust this according to your user model and authentication
            )
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class GraduationView(APIView):
    permission_classes = [IsAuthenticated]  # Ensure only authenticated users can access this view

    def get(self, request):
        classnote = Graduation.objects.all()
        serializer = GraduationSerializer(classnote, many=True, context={'request': request})
        return Response(serializer.data)

    def post(self, request):
        serializer = GraduationSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            classnotes = serializer.save()
            # Create a notification
            Notification.objects.create(
                title="New Class Note",
                message=f"A new class note has been uploaded: {classnotes.title}",
                user=request.user  # Adjust this according to your user model and authentication
            )
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


def policy(request):
    return render(request, 'policy.html')