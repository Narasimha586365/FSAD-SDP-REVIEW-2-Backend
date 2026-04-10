package com.fsad.studentachievement.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

public record VerifyRegistrationOtpRequest(
    @NotBlank @Email String email,
    @NotBlank @Pattern(regexp = "^[6-9][0-9]{9}$") String phone,
    @NotBlank String role,
    @NotBlank @Pattern(regexp = "^[0-9]{6}$") String otp
) {
}