# Generated by Django 5.0.6 on 2024-06-17 22:45

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('backend', '0002_user_username'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='user',
            name='username',
        ),
    ]
