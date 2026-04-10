package com.fsad.studentachievement.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public record RegisterRequest(
    @NotBlank String name,
    @NotBlank @Email String email,
    @NotBlank String password,
    @NotBlank String role,
    @NotBlank String rollNumber,
    @NotBlank String department,
    @NotBlank String cohort
) {
}