package com.fsad.studentachievement.dto;

import jakarta.validation.constraints.NotNull;

public record CoAdminApprovalRequest(@NotNull Integer userId) {
}
