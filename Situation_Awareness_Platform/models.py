from django.db import models

class AttackEvent(models.Model):
    timestamp = models.DateTimeField(auto_now_add=True)
    source_ip = models.CharField(max_length=100)
    destination_ip = models.CharField(max_length=100)
    attack_type = models.CharField(max_length=100)

    class Meta:
        app_label = 'Situation_Awareness_Platform'


class Ip(models.Model):
    ip_address = models.CharField(max_length=50)
    country = models.CharField(max_length=100)
    city = models.CharField(max_length=100)
    latitude = models.FloatField()
    longitude = models.FloatField()
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.ip_address
    
class Apache(models.Model):
    ip = models.CharField(max_length=200)
    time = models.CharField(max_length=200)
    num = models.CharField(max_length=200)
    attack_type = models.CharField(max_length=200)
    raw_request = models.TextField()

    def __str__(self):
        return f"Apache {self.id}"

    def select_event_by_ip(self):
        return Apache.objects.filter(ip=self.ip).values_list('attack_type', flat=True)

