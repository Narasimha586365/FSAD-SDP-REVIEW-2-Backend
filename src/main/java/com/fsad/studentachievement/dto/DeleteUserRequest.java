package com.fsad.studentachievement.dto;

import jakarta.validation.constraints.NotNull;

public record DeleteUserRequest(
    @NotNull Integer userId
) {}
