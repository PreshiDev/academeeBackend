from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models
from django.utils import timezone
from django.conf import settings
import uuid
import secrets
from datetime import date

class CustomUserManager(BaseUserManager):
    def create_user(self, username, password=None, **extra_fields):
        if not username:
            raise ValueError('The Username field must be set')
        user = self.model(username=username, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user
    
    def create_superuser(self, username, password=None, **extra_fields):
      extra_fields.setdefault('is_staff', True)
      extra_fields.setdefault('is_superuser', True)

      if extra_fields.get('is_staff') is not True:
          raise ValueError('Superuser must have is_staff=True.')
      if extra_fields.get('is_superuser') is not True:
          raise ValueError('Superuser must have is_superuser=True.')

      return self.create_user(username, password, **extra_fields)

class CustomUser(AbstractBaseUser, PermissionsMixin):
    username = models.CharField(max_length=255, unique=True)
    email = models.EmailField(unique=True, null=True, blank=True)
    first_name = models.CharField(max_length=255, blank=True)
    last_name = models.CharField(max_length=255, blank=True)
    date_joined = models.DateTimeField(default=timezone.now)
    profile_picture = models.ImageField(upload_to='profile_pictures/', blank=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    
    SUBSCRIPTION_CHOICES = [
        ('none', 'None'),
        ('monthly', 'Monthly'),
        ('quarterly', 'Quarterly'),
        ('annually', 'Annually'),
    ]
    subscription_plan = models.CharField(max_length=10, choices=SUBSCRIPTION_CHOICES, default='none')
    subscription_start_date = models.DateTimeField(null=True, blank=True)
    subscription_end_date = models.DateTimeField(null=True, blank=True)

    objects = CustomUserManager() 

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['email', 'first_name', 'last_name']

    def __str__(self):
        return self.username

    def has_perm(self, perm, obj=None):
        return True

    def has_module_perms(self, app_label):
        return True
    


class CustomToken(models.Model):
    key = models.CharField(max_length=40, primary_key=True)
    user = models.OneToOneField(settings.AUTH_USER_MODEL, related_name='custom_token', on_delete=models.CASCADE)
    created = models.DateTimeField(default=timezone.now)

    def save(self, *args, **kwargs):
        if not self.key:
            self.key = self.generate_key()
        return super().save(*args, **kwargs)

    def generate_key(self):
        return secrets.token_hex(20)

    def __str__(self):
        return self.key

class NewsHeadline(models.Model):
    title = models.CharField(max_length=255)
    content = models.TextField()
    author = models.CharField(max_length=100)
    published_date = models.DateTimeField(default=timezone.now)
    is_published = models.BooleanField(default=True)
    image = models.ImageField(upload_to='news_images/', blank=True, null=True)

    def __str__(self):
        return self.title
    
    
class SchoolCalendar(models.Model):
    title = models.CharField(max_length=255)
    pdf = models.FileField(upload_to='school_calendars/')

    def __str__(self):
        return self.title


class ChatMessage(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    text = models.TextField(blank=True, null=True)
    image = models.ImageField(upload_to='chat_images/', blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    parent = models.ForeignKey('self', null=True, blank=True, related_name='replies', on_delete=models.CASCADE)

    def __str__(self):
        return self.text or 'Image Message'


class VideoComment(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, default=CustomUser.objects.first().id)
    video_id = models.CharField(max_length=100)
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f'Comment on {self.video_id} by {self.id}'

class Notification(models.Model):
    title = models.CharField(max_length=255)
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)  # Assuming you have a CustomUser model
    is_read = models.BooleanField(default=False)  # Add this field

class SchemeWork(models.Model):
    title = models.CharField(max_length=255)
    pdf = models.FileField(upload_to='scheme_work/')

    def __str__(self):
        return self.title
    
class LessonNote(models.Model):
    TERM_CHOICES = [
        ('1', 'First Term'),
        ('2', 'Second Term'),
        ('3', 'Third Term'),
    ]

    CLASS_CHOICES = [
        ('Pre-Nursery', 'Pre-Nursery'),
        ('Nursery', 'Nursery'),
        ('Primary 1', 'Primary 1'),
        ('Primary 2', 'Primary 2'),
        ('Primary 3', 'Primary 3'),
        ('Primary 4', 'Primary 4'),
        ('Primary 5', 'Primary 5'),
        ('Jss 1', 'Jss 1'),
        ('Jss 2', 'Jss 2'),
        ('Jss 3', 'Jss 3'),
        ('Ss 1', 'Ss 1'),
        ('Ss 2', 'Ss 2'),
        ('Ss 3', 'Ss 3'),
        # Add more classes as needed
    ]

    title = models.CharField(max_length=255)
    pdf = models.FileField(upload_to='lesson_notes/')
    term = models.CharField(max_length=1, choices=TERM_CHOICES)
    classes = models.CharField(max_length=50, choices=CLASS_CHOICES)

    def __str__(self):
        return self.title
    
class ExamQuestion(models.Model):
    TERM_CHOICES = [
        ('1', 'First Term'),
        ('2', 'Second Term'),
        ('3', 'Third Term'),
    ]

    CLASS_CHOICES = [
        ('Pre-Nursery', 'Pre-Nursery'),
        ('Nursery', 'Nursery'),
        ('Primary 1', 'Primary 1'),
        ('Primary 2', 'Primary 2'),
        ('Primary 3', 'Primary 3'),
        ('Primary 4', 'Primary 4'),
        ('Primary 5', 'Primary 5'),
        ('Jss 1', 'Jss 1'),
        ('Jss 2', 'Jss 2'),
        ('Jss 3', 'Jss 3'),
        ('Ss 1', 'Ss 1'),
        ('Ss 2', 'Ss 2'),
        ('Ss 3', 'Ss 3'),
        # Add more classes as needed
    ]

    title = models.CharField(max_length=255)
    pdf = models.FileField(upload_to='exam_questions/')
    term = models.CharField(max_length=1, choices=TERM_CHOICES)
    classes = models.CharField(max_length=50, choices=CLASS_CHOICES)

    def __str__(self):
        return self.title
    
class ExamTimetable(models.Model):
    title = models.CharField(max_length=255)
    pdf = models.FileField(upload_to='exam_timetable/')
    year = models.PositiveIntegerField(default=date.today().year)

    def __str__(self):
        return f"{self.title} ({self.year})"
    
class ClassNote(models.Model):
    title = models.CharField(max_length=255)
    pdf = models.FileField(upload_to='class_note/')

    def __str__(self):
        return self.title
    
class ReportComment(models.Model):
    title = models.CharField(max_length=255)
    pdf = models.FileField(upload_to='report_comments/')

    def __str__(self):
        return self.title
    
class AssemblyTopic(models.Model):
    title = models.CharField(max_length=255)
    pdf = models.FileField(upload_to='assembly_topics/')

    def __str__(self):
        return self.title
    
class SchoolActivities(models.Model):
    ACTIVITIES = [
        ('Events', 'Events'),
        ('Letters', 'Letters'),
        ('Speeches', 'Speeches'),
        # Add more classes as needed
    ]
    activities = models.CharField(max_length=10, blank=True, null=True, choices=ACTIVITIES)
    title = models.CharField(max_length=255)
    pdf = models.FileField(upload_to='school_activities/')

    def __str__(self):
        return self.title
    
class WorkBooks(models.Model):
    title = models.CharField(max_length=255)
    pdf = models.FileField(upload_to='work_books/')

    def __str__(self):
        return self.title
    
class ReportSheet(models.Model):
    title = models.CharField(max_length=255)
    pdf = models.FileField(upload_to='report_sheets/')

    def __str__(self):
        return self.title
    
class Announcement(models.Model):
    title = models.CharField(max_length=255)
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

class SchoolPolicies(models.Model):
    title = models.CharField(max_length=255)
    pdf = models.FileField(upload_to='class_note/')

    def __str__(self):
        return self.title
    
class Graduation(models.Model):
    title = models.CharField(max_length=255)
    pdf = models.FileField(upload_to='class_note/')

    def __str__(self):
        return self.title