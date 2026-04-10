package com.fsad.studentachievement.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

public record AchievementRequest(
    @NotNull Integer studentId,
    @NotBlank String title,
    @NotBlank String category,
    @NotBlank String activityCategory,
    @NotBlank String description,
    @NotBlank String date
) {
}