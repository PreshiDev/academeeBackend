from django.contrib import admin
from django.contrib.auth.admin import UserAdmin  # Import UserAdmin class from Django

from .models import CustomUser, NewsHeadline, SchoolCalendar, ChatMessage, Notification, Announcement, VideoComment  # Import your User model

class CustomUserAdmin(UserAdmin):
    model = CustomUser
    fieldsets = (
        (None, {'fields': ('username', 'password')}),
        ('Personal info', {'fields': ('first_name', 'last_name', 'email', 'profile_picture')}),
        ('Permissions', {'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
        ('Important dates', {'fields': ('last_login', 'date_joined')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('username', 'email', 'password1', 'password2', 'is_staff', 'is_active')}
        ),
    )
    list_display = ('username', 'email', 'first_name', 'last_name', 'is_staff')
    search_fields = ('username', 'email')
    ordering = ('username',)

admin.site.register(CustomUser, CustomUserAdmin)
admin.site.register(NewsHeadline)
admin.site.register(SchoolCalendar)
admin.site.register(ChatMessage)
admin.site.register(Notification)
admin.site.register(Announcement)
admin.site.register(VideoComment)