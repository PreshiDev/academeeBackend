# Generated by Django 5.0.6 on 2024-06-29 18:12

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('backend', '0021_remove_newsheadline_id_newsheadline_news_id'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='newsheadline',
            name='news_id',
        ),
        migrations.AddField(
            model_name='newsheadline',
            name='id',
            field=models.BigAutoField(auto_created=True, default=1, primary_key=True, serialize=False, verbose_name='ID'),
            preserve_default=False,
        ),
    ]
