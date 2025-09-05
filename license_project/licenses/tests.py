from django.test import TestCase
from django.test import TestCase, Client
from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient
from unittest.mock import patch
from datetime import timedelta
from django.utils import timezone
from .models import License, AdminSettings

User = get_user_model()
class UserAndAdminViewTests(TestCase):
    def setUp(self):
        self.client=Client()

    def test_first_user_is_superuser(self):
        response=self.client.post(reverse('register'), {
            'username':'firstadmin',
            'email':'admin@example.com',
            'password':'password123',
            'password2':'password123'
        },follow=True)
        self.assertTrue(User.objects.get(username='firstadmin').is_superuser)
        self.assertContains(response,'Welcome! You have been granted admin rights.')

    def test_subsequent_user_is_regular_user(self):
        User.objects.create_user('existinguser', 'existing@example.com', 'password')
        response = self.client.post(reverse('register'), {
            'username':'regularuser',
            'email':'regular@example.com',
            'password':'password123',
            'password2':'password123'
        }, follow=True)
        self.assertFalse(User.objects.get(username='regularuser').is_superuser)
        self.assertContains(response,'Registration successful!')

class LicenseModelTests(TestCase):
    def test_key_encryption_decryption(self):
        license=License(user=User.objects.create_user('testuser'), expires_at=timezone.now() + timedelta(days=30))
        raw_key="LIC-TEST-KEY-12345"
        password="mysecretpassword"
        license.set_license_view_password_and_encrypt_key(password, raw_key)
        license.save()
        self.assertNotEqual(license.key, raw_key)
        decrypted_key=license.decrypt_actual_key(password)
        self.assertEqual(decrypted_key, raw_key)
        self.assertIsNone(license.decrypt_actual_key("wrongpassword"))

    def test_license_validity(self):
        valid_license=License(status='active',expires_at=timezone.now()+timedelta(days=10))
        self.assertTrue(valid_license.is_valid)
        expired_license=License(status='active',expires_at=timezone.now()-timedelta(days=1))
        self.assertFalse(expired_license.is_valid)
        revoked_license=License(status='revoked',expires_at=timezone.now()+timedelta(days=10))
        self.assertFalse(revoked_license.is_valid)

class LicenseAPIViewTests(TestCase):
    def setUp(self):
        self.client=APIClient()
        self.admin=User.objects.create_superuser('admin','admin@example.com','password123')
        self.user=User.objects.create_user('user','user@example.com','password123')
        self.license=License.objects.create(user=self.user, expires_at=timezone.now()+timedelta(days=30))
        self.license.set_license_view_password_and_encrypt_key('pass','rawkey')
        self.license.save()

    def test_validate_license_api_success(self):
        self.client.force_authenticate(user=self.user)
        url=reverse('validate_license')
        data={'license_key':self.license.key}
        response=self.client.post(url,data,format='json')
        self.assertEqual(response.status_code,status.HTTP_200_OK)
        self.assertTrue(response.data['valid'])

    def test_validate_license_api_invalid(self):
        self.client.force_authenticate(user=self.user)
        url=reverse('validate_license')
        data={'license_key':'invalid-key'}
        response=self.client.post(url,data,format='json')
        self.assertEqual(response.status_code,status.HTTP_200_OK)
        self.assertFalse(response.data['valid'])
    
    @patch('brevo_python.TransactionalEmailsApi.send_transac_email')
    def test_license_request_sends_email(self, mock_send_email):
        AdminSettings.objects.create(license_request_email='admin@example.com')
        response = self.client.post(reverse('license-request'),{
            'requester_email':'request@example.com',
            'requirements':'I need a license for my app.'
        })
        self.assertEqual(response.status_code,302) 
        self.assertTrue(mock_send_email.called)
