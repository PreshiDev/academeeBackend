# Generated by Django 5.0.6 on 2024-08-29 20:20

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('backend', '0046_customuser_phone'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='customuser',
            name='phone',
        ),
    ]
