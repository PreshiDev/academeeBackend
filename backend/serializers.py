from rest_framework import serializers
from .models import CustomUser, NewsHeadline, SchoolCalendar, ChatMessage, VideoComment, Notification, LessonNote, SchemeWork, ExamQuestion, ExamTimetable, ClassNote, ReportComment, AssemblyTopic, SchoolActivities, WorkBooks, ReportSheet, Announcement, SchoolPolicies, Graduation, NewsComment
from django.contrib.auth import authenticate
import logging
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer



logger = logging.getLogger(__name__)
User = get_user_model()



class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ('username', 'first_name', 'last_name', 'email', 'phone_number', 'profile_picture', 'password')
        extra_kwargs = {
            'password': {'write_only': True},
        }

    def create(self, validated_data):
        user = CustomUser.objects.create_user(
            email=validated_data['email'],
            username=validated_data['username'],
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name'],
            password=validated_data['password']
        )
        if 'profile_picture' in validated_data:
            user.profile_picture = validated_data['profile_picture']
        user.save()
        return user


class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        username = data.get('username')
        password = data.get('password')

        if username and password:
            user = authenticate(username=username, password=password)
            if user:
                if not user.is_active:
                    raise serializers.ValidationError("User account is not active.")
                data['user'] = user
            else:
                raise serializers.ValidationError("Invalid credentials")
        else:
            raise serializers.ValidationError("Must include 'username' and 'password'")

        return data
    
class NewsHeadlineSerializer(serializers.ModelSerializer):
    image_url = serializers.SerializerMethodField()

    class Meta:
        model = NewsHeadline
        fields = ['id', 'title', 'content', 'author', 'image', 'image_url', 'published_date']
        read_only_fields = ['image_url']

    def get_image_url(self, obj):
        if obj.image:
            return self.context['request'].build_absolute_uri(obj.image.url)
        return None
    
class SchoolCalendarSerializer(serializers.ModelSerializer):
    pdf = serializers.FileField(required=False)  # Ensure the field can be omitted in requests

    class Meta:
        model = SchoolCalendar
        fields = ['id', 'title', 'pdf']

    def get_pdf(self, obj):
        request = self.context.get('request')
        if obj.pdf:
            return request.build_absolute_uri(obj.pdf.url)
        return None
 
class ChatMessageSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)

    class Meta:
        model = ChatMessage
        fields = ['id', 'text', 'image', 'created_at', 'user', 'replies']
        read_only_fields = ['user', 'replies']

    def get_user_name(self, obj):
        return obj.user.username if obj.user else None

    def get_profile_picture(self, obj):
        request = self.context.get('request')
        profile_picture_url = obj.user.profile_picture.url if obj.user.profile_picture else None
        return request.build_absolute_uri(profile_picture_url) if profile_picture_url else None

    def get_replies(self, obj):
        if obj.replies:
            return ChatMessageSerializer(obj.replies.all(), many=True, context=self.context).data
        return []

class ChatMessageReplySerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    class Meta:
        model = ChatMessage
        fields = ['id', 'user', 'text', 'created_at']

class VideoCommentSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)  # or 'user.id' if you want to return the user id

    class Meta:
        model = VideoComment
        fields = ['id', 'video_id', 'content', 'created_at', 'user']

    def create(self, validated_data):
        request = self.context.get('request')
        user = request.user
        validated_data['user'] = user
        return super().create(validated_data)


class NewsCommentSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)  # Assuming you have a UserSerializer to represent the user

    class Meta:
        model = NewsComment
        fields = ['id', 'news', 'content', 'created_at', 'user']

    def create(self, validated_data):
        request = self.context.get('request')
        user = request.user
        validated_data['user'] = user
        return super().create(validated_data)


class UserDetailSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ('username', 'first_name', 'last_name', 'email', 'profile_picture')


class UserUpdateSerializer(serializers.ModelSerializer):
    profile_picture = serializers.ImageField(allow_null=True, required=False)

    class Meta:
        model = CustomUser
        fields = ('username', 'first_name', 'last_name', 'email', 'profile_picture', 'subscription_plan', 'subscription_start_date', 'subscription_end_date')
        extra_kwargs = {
            'username': {'required': False},
            'first_name': {'required': False},
            'last_name': {'required': False},
            'email': {'required': False},
            'subscription_plan': {'required': False}, 
            'subscription_start_date': {'required': False}, 
            'subscription_end_date': {'required': False},
        }

    def update(self, instance, validated_data):
        for attr, value in validated_data.items():
            if attr == 'password':
                instance.set_password(value)
            else:
                setattr(instance, attr, value)
        instance.save()
        return instance
    

class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):

    @classmethod
    def get_token(cls, user):
        print("I GOT HERE O")
        token = super().get_token(user)

        # Add custom claims
        token['is_active'] = user.is_active
        token['is_staff'] = user.is_staff
        token['is_superuser'] = user.is_superuser

        logger.debug(f"Token generated for user {user.id}: {token}")

        return token


class NotificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Notification
        fields = ['id', 'title', 'message', 'created_at', 'user', 'is_read']

class SchemeWorkSerializer(serializers.ModelSerializer):
    pdf = serializers.FileField(required=False)  # Ensure the field can be omitted in requests

    class Meta:
        model = SchemeWork
        fields = ['id', 'title', 'pdf']

    def get_pdf(self, obj):
        request = self.context.get('request')
        if obj.pdf:
            return request.build_absolute_uri(obj.pdf.url)
        return None


class LessonNoteSerializer(serializers.ModelSerializer):
    pdf = serializers.FileField(required=False)  # Ensure the field can be omitted in requests

    class Meta:
        model = LessonNote
        fields = ['id', 'title', 'pdf', 'term', 'classes']

    def get_pdf(self, obj):
        request = self.context.get('request')
        if obj.pdf:
            return request.build_absolute_uri(obj.pdf.url)
        return None
    


class ExamQuestionSerializer(serializers.ModelSerializer):
    pdf = serializers.FileField(required=False)  # Ensure the field can be omitted in requests

    class Meta:
        model = ExamQuestion
        fields = ['id', 'title', 'pdf', 'term', 'classes']

    def get_pdf(self, obj):
        request = self.context.get('request')
        if obj.pdf:
            return request.build_absolute_uri(obj.pdf.url)
        return None
    

class ExamTimetableSerializer(serializers.ModelSerializer):
    pdf = serializers.FileField(required=False)  # Ensure the field can be omitted in requests

    class Meta:
        model = ExamTimetable
        fields = ['id', 'title', 'pdf', 'year']  # Include year field

    def get_pdf(self, obj):
        request = self.context.get('request')
        if obj.pdf:
            return request.build_absolute_uri(obj.pdf.url)
        return None


class ClassNoteSerializer(serializers.ModelSerializer):
    pdf = serializers.FileField(required=False)  # Ensure the field can be omitted in requests

    class Meta:
        model = ClassNote
        fields = ['id', 'title', 'pdf']

    def get_pdf(self, obj):
        request = self.context.get('request')
        if obj.pdf:
            return request.build_absolute_uri(obj.pdf.url)
        return None


class ReportCommentSerializer(serializers.ModelSerializer):
    pdf = serializers.FileField(required=False)  # Ensure the field can be omitted in requests

    class Meta:
        model = ReportComment
        fields = ['id', 'title', 'pdf']

    def get_pdf(self, obj):
        request = self.context.get('request')
        if obj.pdf:
            return request.build_absolute_uri(obj.pdf.url)
        return None


class AssemblyTopicSerializer(serializers.ModelSerializer):
    pdf = serializers.FileField(required=False)  # Ensure the field can be omitted in requests

    class Meta:
        model = AssemblyTopic
        fields = ['id', 'title', 'pdf']

    def get_pdf(self, obj):
        request = self.context.get('request')
        if obj.pdf:
            return request.build_absolute_uri(obj.pdf.url)
        return None


class SchoolActivitiesSerializer(serializers.ModelSerializer):
    pdf = serializers.FileField(required=False)  # Ensure the field can be omitted in requests

    class Meta:
        model = SchoolActivities
        fields = ['id', 'activities', 'title', 'pdf']

    def get_pdf(self, obj):
        request = self.context.get('request')
        if obj.pdf:
            return request.build_absolute_uri(obj.pdf.url)
        return None


class WorkBookSerializer(serializers.ModelSerializer):
    pdf = serializers.FileField(required=False)  # Ensure the field can be omitted in requests

    class Meta:
        model = WorkBooks
        fields = ['id', 'title', 'pdf']

    def get_pdf(self, obj):
        request = self.context.get('request')
        if obj.pdf:
            return request.build_absolute_uri(obj.pdf.url)
        return None


class ReportSheetSerializer(serializers.ModelSerializer):
    pdf = serializers.FileField(required=False)  # Ensure the field can be omitted in requests

    class Meta:
        model = ReportSheet
        fields = ['id', 'title', 'pdf']

    def get_pdf(self, obj):
        request = self.context.get('request')
        if obj.pdf:
            return request.build_absolute_uri(obj.pdf.url)
        return None

class AnnouncementSerializer(serializers.ModelSerializer):
    class Meta:
        model = Announcement
        fields = ['id', 'title', 'message', 'created_at',]

class SchoolPoliciesSerializer(serializers.ModelSerializer):
    pdf = serializers.FileField(required=False)  # Ensure the field can be omitted in requests

    class Meta:
        model = SchoolPolicies
        fields = ['id', 'title', 'pdf']

    def get_pdf(self, obj):
        request = self.context.get('request')
        if obj.pdf:
            return request.build_absolute_uri(obj.pdf.url)
        return None
    
class GraduationSerializer(serializers.ModelSerializer):
    pdf = serializers.FileField(required=False)  # Ensure the field can be omitted in requests

    class Meta:
        model = Graduation
        fields = ['id', 'title', 'pdf']

    def get_pdf(self, obj):
        request = self.context.get('request')
        if obj.pdf:
            return request.build_absolute_uri(obj.pdf.url)
        return None