package com.fsad.studentachievement.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

public record PasswordResetConfirmRequest(
    @NotBlank @Email String email,
    @NotBlank String role,
    @NotBlank @Pattern(regexp = "^[0-9]{6}$") String otp,
    @NotBlank String newPassword
) {
}