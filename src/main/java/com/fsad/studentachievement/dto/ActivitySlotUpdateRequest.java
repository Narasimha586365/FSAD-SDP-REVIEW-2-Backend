package com.fsad.studentachievement.dto;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;

public record ActivitySlotUpdateRequest(
    @NotNull Integer activityId,
    @NotNull @Min(1) Integer slots
) {
}
