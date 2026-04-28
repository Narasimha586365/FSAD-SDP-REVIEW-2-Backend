package com.fsad.studentachievement;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class StudentAchievementPlatformBackendApplication {

    public static void main(String[] args) {
        if (System.getenv("DB_URL") == null) {
            System.setProperty("spring.datasource.url", "jdbc:mysql://mysql-2b9ab9e8-pnnaidu2006-8642.a.aivencloud.com:14624/defaultdb?sslMode=REQUIRED");
            System.setProperty("spring.datasource.username", "avnadmin");
            System.setProperty("spring.datasource.password", new String(java.util.Base64.getDecoder().decode("QVZOU19FbUVMTGpkQ1V3aUdpM1E2ay1y")));
        }
        SpringApplication.run(StudentAchievementPlatformBackendApplication.class, args);
    }
}