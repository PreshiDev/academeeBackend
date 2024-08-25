# Generated by Django 5.0.6 on 2024-08-06 22:49

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('backend', '0037_remove_announcement_is_read_remove_announcement_user'),
    ]

    operations = [
        migrations.AddField(
            model_name='videocomment',
            name='user',
            field=models.ForeignKey(default=1, on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL),
        ),
    ]
