package com.fsad.studentachievement.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

public record RegistrationOtpRequest(
    @NotBlank String name,
    @NotBlank @Email String email,
    @NotBlank @Pattern(regexp = "^[6-9][0-9]{9}$", message = "Phone number must be 10 digits") String phone,
    @NotBlank String role,
    @NotBlank String rollNumber,
    @NotBlank String department,
    @NotBlank String cohort
) {
}