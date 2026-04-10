package com.fsad.studentachievement.dto;

import jakarta.validation.constraints.NotNull;

public record CertificateRequest(@NotNull Integer userId, @NotNull Integer moduleId) {
}