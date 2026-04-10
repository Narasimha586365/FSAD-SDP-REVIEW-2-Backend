package com.fsad.studentachievement.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

public record IssueAchievementRequest(
    @NotNull Integer attemptId,
    @NotBlank String title,
    @NotBlank String category,
    @NotBlank String description
) {
}
