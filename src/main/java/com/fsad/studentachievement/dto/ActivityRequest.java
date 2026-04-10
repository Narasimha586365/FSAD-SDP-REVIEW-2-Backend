package com.fsad.studentachievement.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;

public record ActivityRequest(
    @NotBlank String activityName,
    @NotBlank String activityCategory,
    @NotNull Integer domainId,
    @NotBlank String role,
    @NotBlank String duration,
    @NotBlank String skills,
    @NotBlank String startDate,
    @NotBlank String endDate,
    @NotNull @Positive Integer slots
) {
}
