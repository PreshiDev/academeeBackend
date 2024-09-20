from django.urls import path
from rest_framework_simplejwt.views import (
    TokenRefreshView,
)
from .views import (
    register_view, 
    SubscribeView, 
    NotificationListView, 
    ResetNotificationCountView, 
    LoginView, 
    GetCSRFToken, 
    LatestNewsListView, 
    AllNewsListView, 
    News, 
    NewsCreateView, 
    SchoolCalendarListView, 
    SchemeWorkListView, 
    LessonNoteView, 
    ExamQuestionView, 
    ExamTimetableView, 
    ClassNoteView, 
    ReportCommentView, 
    AssemblyTopicView, 
    SchoolActivitiesView, 
    WorkBookView, 
    ReportSheetView, 
    ChatMessageListCreateAPIView, 
    ChatReplyCreateAPIView, 
    ChatMessageReplyListAPIView, 
    VideoCommentListCreateView, 
    user_detail_view, 
    UserUpdateView, 
    UserViewSet, 
    CustomTokenObtainPairView, 
    CustomTokenRefreshView,
    TermClassChoicesView,
    ExamTermClassChoicesView,
    SchoolActivityChoicesView,
    AnnouncementListView, 
    AnnouncementCreateView,
    get_counts,
    SchoolPoliciesView,
    GraduationView,
    AvailableYearsView,
    NewsCommentListCreateView,
    policy,
  )

urlpatterns = [
  path('api/user/profile/', UserViewSet.as_view(), name='user-detail'),
  path('api/user/', user_detail_view, name='user-detail'),
  path('api/user/update/', UserUpdateView.as_view(), name='user-update'),
  path('api/token/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
  path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
  path('api/register/', register_view, name='register'),
  path('api/login/', LoginView.as_view(), name='login'),
  path('api/csrf-token/', GetCSRFToken.as_view(), name='csrf-token'),
  path('api/latest/', LatestNewsListView.as_view(), name='latest-news'),
  path('news/all/', AllNewsListView.as_view(), name='all-news'),
  path('api/news/<int:id>/', News.as_view(), name='news'),
  path('api/create/', NewsCreateView.as_view(), name='create-news'),
  path('api/calendars/', SchoolCalendarListView.as_view(), name='school-calendar-list'),
  path('api/schemework/', SchemeWorkListView.as_view(), name='scheme-work-list'),
  path('api/lessonnote/', LessonNoteView.as_view(), name='lesson-note'),
  path('api/examquestion/', ExamQuestionView.as_view(), name='exam-question'),
  path('api/examtimetable/', ExamTimetableView.as_view(), name='exam-timetable'),
  path('api/examtimetable/years/', AvailableYearsView.as_view(), name='available-years'),
  path('api/classnote/', ClassNoteView.as_view(), name='class-note'),
  path('api/reportcomment/', ReportCommentView.as_view(), name='report-comment'),
  path('api/assemblytopic/', AssemblyTopicView.as_view(), name='assembly-topic'),
  path('api/schoolactivities/', SchoolActivitiesView.as_view(), name='school-activities'),
  path('api/workbook/', WorkBookView.as_view(), name='work-book'),
  path('api/reportsheet/', ReportSheetView.as_view(), name='report-sheet'),
  path('api/chat/', ChatMessageListCreateAPIView.as_view(), name='chat-message-list-create'),
  path('api/chat/<int:parent_id>/reply/', ChatReplyCreateAPIView.as_view(), name='chat-reply-create'),
  path('api/chat/<int:parent_id>/replies/', ChatMessageReplyListAPIView.as_view(), name='chat-reply-list'),
  path('api/comments/', VideoCommentListCreateView.as_view(), name='video-comment-list-create'),
  path('api/new_comments/', NewsCommentListCreateView.as_view(), name='news-comment-list-create'),
  path('api/subscribe/', SubscribeView.as_view(), name='subscribe'),
  path('api/notifications/', NotificationListView.as_view(), name='notification-list'),
  path('api/notifications/reset-count/<int:id>', ResetNotificationCountView.as_view(), name='reset-notification-count'),
  path('api/lessonchoices/', TermClassChoicesView.as_view(), name='term-class-choices'),
  path('api/questionchoices/', ExamTermClassChoicesView.as_view(), name='question-term-class-choices'),
  path('api/activitychoices/', SchoolActivityChoicesView.as_view(), name='school-activity-choices'),
  path('api/announcements/', AnnouncementListView.as_view(), name='announcement-list'),
  path('api/announcements/create/', AnnouncementCreateView.as_view(), name='announcement-create'),
  path('api/schoolpolicies/', SchoolPoliciesView.as_view(), name='school-policies'),
  path('api/graduationday/', GraduationView.as_view(), name='graduation-day'),
  path('api/get-counts/', get_counts, name='get-counts'),
  path('policy/', policy, name='policy'),
]
