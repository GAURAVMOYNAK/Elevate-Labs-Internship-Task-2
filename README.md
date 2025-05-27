# Elevate-Labs-Internship-Task-2
# Phishing Email Analysis Report

## 1. Email Metadata

- **Subject:** URGENT: Your Amazon Account Has Been Locked  
- **From Name:** "Amazon Security"  
- **From Address:** support@amaz0n-secure.com  
- **Return-Path:** support@amazon-payment.ru  
- **Received From Server:** compromised-server.ru  
- **IP Source:** 203.0.113.45  
- **Reverse DNS Lookup:** Not found (PTR record missing)  
- **Date Received:** 27 May 2025  
- **Attachments:** None  

---

## 2. Header Authentication Analysis

- **SPF (Sender Policy Framework):** Failed  
  - The IP address of the sending server is not authorized to send emails on behalf of the spoofed domain.
  
- **DKIM (DomainKeys Identified Mail):** Failed  
  - The message did not have a valid digital signature aligned with the sender domain.
  
- **DMARC (Domain-based Message Authentication, Reporting and Conformance):** Failed  
  - No alignment with SPF or DKIM records, and domain policy failed validation.

---

## 3. Domain and IP Analysis

- **Spoofed Domain:** `amaz0n-secure.com` (note use of zero instead of letter 'o')
- **Return-Path Domain:** `amazon-payment.ru` – unrelated to Amazon, suspicious TLD
- **IP Address:** 203.0.113.45
- **PTR Record (Reverse DNS):** Not found
- **NSLOOKUP Result:** IP has no valid DNS records
- **Hosting Origin:** IP traced to a suspicious or compromised server not owned by Amazon

---

## 4. Email Body Content Analysis

- **Greeting:** Generic ("Dear Customer") – indicates mass phishing
- **Tone and Language:** Urgent, threatening tone used to induce panic
- **Grammar and Formatting:** Poor sentence structure, missing punctuation, inconsistent formatting
- **Call to Action:** Requests user to click on a verification link urgently
- **Fake Support Number:** Lists +1 (800) 123-4567 – a generic, unregistered number
- **Link Preview (on hover):** 
  - Displayed as: “Click here to verify”
  - Redirects to: `http://amaz0n-secure-login.com/verify`

---

## 5. Technical Observations

- **WHOIS Lookup:** Domain `amaz0n-secure.com` was anonymously registered through a domain masking service recently
- **SSL Certificate:** No valid SSL certificate on the phishing URL
- **Redirect Behavior:** Link leads to a login page mimicking Amazon's layout, used to steal credentials
- **Visual Appearance:** Email attempts to imitate Amazon branding but lacks proper formatting, official footers, or contact details
- **No Personalization:** No mention of user’s name or account info

---

## 6. Summary of Phishing Indicators

| Indicator | Description |
|----------|-------------|
| Fake Domain | `amaz0n-secure.com` uses character substitution (zero instead of 'o') |
| Failed SPF, DKIM, DMARC | Email authentication mechanisms did not validate the source |
| Suspicious Return-Path | Return address points to `.ru` domain unrelated to Amazon |
| Generic Greeting | Lack of personalization, common in phishing |
| Urgent Language | Creates panic to rush user into action |
| Poor Grammar | Non-professional writing, not consistent with corporate standards |
| Suspicious Link | Redirects to malicious site not associated with Amazon |
| Fake Contact Number | Generic number, not traceable to Amazon support |
| No Reverse DNS | Sending IP address lacks PTR record and proper DNS setup |

---

## 7. Conclusion

Based on header analysis, content examination, domain/IP investigation, and phishing heuristics, this email is a confirmed **phishing attack**. The attacker aims to harvest user credentials by imitating a known brand (Amazon) through social engineering and technical spoofing techniques.

### Recommendation

- Do **not** click any links or respond to the email.  
- Immediately report the phishing attempt to your organization's security team or email provider.  
- If any credentials were submitted, change the password and enable multi-factor authentication immediately.  

---

## 8. Appendix: Sample Email Content (Raw)

### Email Headers
```plaintext
From: Amazon Security <support@amaz0n-secure.com>
Return-Path: <support@amazon-payment.ru>
Subject: URGENT: Your Amazon Account Has Been Locked
Received: from compromised-server.ru (203.0.113.45)
SPF: FAIL
DKIM: FAIL
DMARC: FAIL
Date: Mon, 27 May 2025 08:30:12 +0000
Message-ID: <suspicious001@amaz0n-secure.com>
MIME-Version: 1.0
Content-Type: text/html; charset="UTF-8"


Dear Customer,

We have detected unusual activity in your Amazon account and as a result, it has been temporarily locked for security reasons.

To restore full access, please verify your identity by clicking the link below:

[Click here to verify your account](http://amaz0n-secure-login.com/verify)

Failure to verify within 24 hours will result in permanent suspension of your account.

For assistance, please contact our support team at +1 (800) 123-4567.

Sincerely,  
Amazon Security Team
```

*Note: The above link is malicious and has been intentionally obfuscated here for safety.*

---

## 9. Tools Used

- **Header Analyzer:** mxtoolbox.com, mailheader.org  
- **WHOIS Lookup:** who.is  
- **NSLOOKUP/Dig:** command-line tools  
- **Reverse DNS / IP Info:** dnschecker.org, ipinfo.io  
- **SPF/DKIM/DMARC Check:** dmarcian.com, mail-tester.com  
- **Email Client Used:** Thunderbird (for raw header export)

---

