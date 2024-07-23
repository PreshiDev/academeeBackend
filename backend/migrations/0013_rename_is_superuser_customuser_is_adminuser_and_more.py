# Generated by Django 5.0.6 on 2024-06-22 12:20

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('backend', '0012_rename_user_customuser'),
    ]

    operations = [
        migrations.RenameField(
            model_name='customuser',
            old_name='is_superuser',
            new_name='is_adminuser',
        ),
        migrations.AlterField(
            model_name='customuser',
            name='email',
            field=models.EmailField(blank=True, max_length=254, null=True, unique=True),
        ),
        migrations.AlterField(
            model_name='customuser',
            name='username',
            field=models.CharField(max_length=255, unique=True),
        ),
    ]
