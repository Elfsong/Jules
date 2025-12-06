import random
from datetime import datetime

class PhishingGenerator:
    def __init__(self):
        self.templates = {
            'password_reset': {
                'subject': "Action Required: Password Reset for {service}",
                'body': """
Dear {target_name},

We received a request to reset your password for your {service} account.

If you made this request, please click the link below to reset your password:
{link}

If you did not make this request, please ignore this email or contact support.

Best regards,
The {service} Security Team
                """
            },
            'urgent_update': {
                'subject': "URGENT: Update your account information immediately",
                'body': """
Hello {target_name},

We noticed suspicious activity on your {service} account. To prevent your account from being locked, you must verify your identity immediately.

Click here to verify:
{link}

Failure to verify within 24 hours will result in permanent account suspension.

Sincerely,
{service} Support
                """
            }
        }

    def generate_email(self, template_type, target_name, service, link):
        """
        Generates a phishing email content based on a template.

        :param template_type: 'password_reset' or 'urgent_update'
        :param target_name: Name of the target
        :param service: Name of the service (e.g., Company Portal)
        :param link: The simulated phishing link
        :return: A dictionary with subject and body
        """
        if template_type not in self.templates:
            return {'error': 'Template not found'}

        template = self.templates[template_type]
        subject = template['subject'].format(service=service)
        body = template['body'].format(target_name=target_name, service=service, link=link)

        return {
            'template': template_type,
            'subject': subject,
            'body': body.strip(),
            'generated_at': datetime.now().isoformat()
        }

if __name__ == "__main__":
    gen = PhishingGenerator()
    email = gen.generate_email('password_reset', 'John Doe', 'Corporate VPN', 'http://fake-vpn-portal.com/login')
    print(f"Subject: {email['subject']}")
    print(f"Body:\n{email['body']}")
