package com.fsad.studentachievement.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

import jakarta.mail.internet.MimeMessage;
import jakarta.mail.util.ByteArrayDataSource;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@RequiredArgsConstructor
@Slf4j
public class MailService {

    private final JavaMailSender mailSender;

    @Value("${mail.enabled:false}")
    private boolean mailEnabled;

    @Value("${mail.from:no-reply@student-achievement.local}")
    private String fromAddress;

    public boolean sendMail(String to, String subject, String text) {
        if (!mailEnabled) {
            log.info("Mail disabled. To: {} Subject: {} Body: {}", to, subject, text);
            return false;
        }
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, false);
            helper.setFrom(fromAddress);
            helper.setTo(to);
            helper.setSubject(subject);
            helper.setText(text, false);
            mailSender.send(message);
            return true;
        } catch (Exception exception) {
            log.error("Unable to send mail to {}", to, exception);
            return false;
        }
    }

    public boolean sendMailWithAttachment(String to, String subject, String text, byte[] attachment, String filename, String contentType) {
        if (!mailEnabled) {
            log.info("Mail disabled. To: {} Subject: {} Attachment: {}", to, subject, filename);
            return false;
        }
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true);
            helper.setFrom(fromAddress);
            helper.setTo(to);
            helper.setSubject(subject);
            helper.setText(text, false);
            helper.addAttachment(filename, new ByteArrayDataSource(attachment, contentType));
            mailSender.send(message);
            return true;
        } catch (Exception exception) {
            log.error("Unable to send mail with attachment to {}", to, exception);
            return false;
        }
    }
}
