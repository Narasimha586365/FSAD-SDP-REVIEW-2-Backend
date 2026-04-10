package com.fsad.studentachievement.dto;

import jakarta.validation.constraints.NotNull;

public record EnrollmentRequest(@NotNull Integer studentId, @NotNull Integer activityId) {
}