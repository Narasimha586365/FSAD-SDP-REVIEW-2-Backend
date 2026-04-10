package com.fsad.studentachievement.dto;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;

public record PlatformLimitsRequest(
    @NotNull @Min(1) Integer studentLimit,
    @NotNull @Min(0) Integer coAdminLimit
) {
}
