package com.fsad.studentachievement.dto;

import jakarta.validation.constraints.NotNull;

public record TestAccessRequest(@NotNull Integer enrollmentId) {
}
