# Generated by Django 5.0.6 on 2024-06-29 17:43

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('backend', '0018_alter_newsheadline_id'),
    ]

    operations = [
        migrations.AlterField(
            model_name='newsheadline',
            name='id',
            field=models.AutoField(auto_created=True, primary_key=True, serialize=False),
        ),
    ]
